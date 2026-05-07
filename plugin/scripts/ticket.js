#!/usr/bin/env node
/**
 * /tracker-ticket <subcommand> ... — duse-ai-plugin ticket integration.
 *
 * Subcommands:
 *   start KEY       open a segment for KEY in current session (closes previous)
 *   end             close any open segment in current session
 *   context KEY     fetch jira ticket context (description, comments, links, ...)
 *   done            close open segment + writeback summaries to jira (each segment)
 *
 * Reads ~/.claude/tracker.json for { server, token } and CLAUDE_SESSION_ID env
 * (set by Claude Code) to know which session we're in.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");

function loadConfig() {
  const candidates = [
    process.env.CLAUDE_TRACKER_CONFIG,
    path.join(os.homedir(), ".claude", "tracker.json"),
    path.join(os.homedir(), ".config", "claude-tracker", "config.json"),
  ].filter(Boolean);
  for (const p of candidates) {
    try { if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf8")); } catch {}
  }
  return {};
}

async function call(method, pathName, body) {
  const cfg = loadConfig();
  // Plugin stores `endpoint` as full events URL (e.g. https://x.workers.dev/events).
  // Derive API base by stripping trailing /events.
  const endpoint = cfg.endpoint || process.env.CLAUDE_TRACKER_ENDPOINT || cfg.server;
  const token = cfg.token || process.env.CLAUDE_TRACKER_TOKEN;
  if (!endpoint || !token) throw new Error("tracker.json에 endpoint/token 없음 — /tracker-config 실행");
  const base = endpoint.replace(/\/events\/?$/, "").replace(/\/$/, "");
  const url = base + pathName;
  const res = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = { _raw: text }; }
  if (!res.ok) throw new Error(json.error || json.detail || `HTTP ${res.status}`);
  return json;
}

function sessionId() {
  const fromEnv = process.env.CLAUDE_SESSION_ID || process.env.SESSION_ID || process.env.CC_SESSION_ID;
  if (fromEnv) return fromEnv;
  // Fallback: hook.js writes per-cwd file; pick the one matching cwd, or .latest.
  try {
    const dir = path.join(os.homedir(), ".claude", "tracker-sessions");
    const safeKey = process.cwd().replace(/[^a-zA-Z0-9._-]/g, "_").slice(-100);
    const cwdFile = path.join(dir, safeKey);
    if (fs.existsSync(cwdFile)) return fs.readFileSync(cwdFile, "utf8").trim();
    const latest = path.join(dir, ".latest");
    if (fs.existsSync(latest)) return JSON.parse(fs.readFileSync(latest, "utf8")).session_id || "";
  } catch {}
  return "";
}

function fmtCtx(c) {
  const lines = [];
  lines.push(`🎫 ${c.key} — ${c.summary || ""}`);
  lines.push(`상태: ${c.status || "?"}${c.priority ? `  우선순위: ${c.priority}` : ""}${c.duedate ? `  기한: ${c.duedate}` : ""}${c.issuetype ? `  유형: ${c.issuetype}` : ""}`);
  if (c.assignee) lines.push(`담당: ${c.assignee}${c.reporter ? `  보고: ${c.reporter}` : ""}`);
  if (c.parent) lines.push(`상위: ${c.parent.key} ${c.parent.type ? `(${c.parent.type})` : ""} — ${c.parent.summary || ""}`);
  if (c.sprint) lines.push(`스프린트: ${c.sprint.name}${c.sprint.state ? ` [${c.sprint.state}]` : ""}${c.sprint.goal ? `  goal: ${c.sprint.goal}` : ""}`);
  if (c.description) {
    lines.push("");
    lines.push("## Description");
    lines.push(c.description);
  }
  if ((c.links || []).length) {
    lines.push("");
    lines.push("## Links");
    for (const l of c.links) lines.push(`- ${l.rel || l.type}: ${l.key} [${l.status || "?"}] ${l.summary || ""}`);
  }
  if ((c.comments || []).length) {
    lines.push("");
    lines.push(`## Recent comments (${c.comments.length})`);
    for (const cm of c.comments) {
      lines.push(`- **${cm.author || "?"}** (${(cm.created || "").slice(0,10)})`);
      const body = (cm.body || "").split("\n").map(s => "  " + s).join("\n");
      lines.push(body);
    }
  }
  if ((c.confluence || []).length) {
    lines.push("");
    lines.push(`## Confluence (${c.confluence.length}개 관련 문서)`);
    for (const p of c.confluence) {
      const tag = p.source === "linked" ? "🔗 링크됨" : "🔍 검색";
      lines.push(`### ${tag} · ${p.title || "(제목 없음)"}${p.space ? `  [${p.space}]` : ""}`);
      if (p.body) {
        for (const ln of p.body.split("\n").slice(0, 12)) lines.push(ln);
      }
      if (p.url) lines.push(`   ↗ ${p.url}`);
      lines.push("");
    }
  }
  if (c.url) { lines.push(""); lines.push(`Jira: ${c.url}`); }
  return lines.join("\n");
}

(async () => {
  const sub = process.argv[2];
  const arg = process.argv[3];
  const sid = sessionId();
  try {
    if (sub === "context") {
      if (!arg) throw new Error("usage: /tracker-ticket context <KEY>");
      const c = await call("GET", `/api/tickets/${encodeURIComponent(arg.toUpperCase())}/context`);
      console.log(fmtCtx(c));
    } else if (sub === "start") {
      if (!arg) throw new Error("usage: /tracker-ticket start <KEY>");
      if (!sid) throw new Error("CLAUDE_SESSION_ID not set — run inside Claude Code");
      const r = await call("POST", `/api/sessions/${encodeURIComponent(sid)}/segments/start`, { ticket_key: arg.toUpperCase() });
      console.log(`✓ ${r.ticket_key} segment 시작 (${(r.started_at || "").replace("T"," ").replace(/\..+$/,"")})`);
      if (r.context) { console.log(""); console.log(fmtCtx(r.context)); }
    } else if (sub === "end") {
      if (!sid) throw new Error("CLAUDE_SESSION_ID not set");
      const r = await call("POST", `/api/sessions/${encodeURIComponent(sid)}/segments/end`, {});
      console.log(`✓ ${r.closed}개 segment 종료`);
    } else if (sub === "list" || sub === "mine") {
      // segments 없으면 본인 미완료 티켓을 후보로 보여줌 (사용자 친화)
      const segs = sid ? await call("GET", `/api/sessions/${encodeURIComponent(sid)}/segments`).catch(() => []) : [];
      if (segs.length && sub !== "mine") {
        console.log(`▷ 현재 세션 segments (${segs.length}개)`);
        for (const s of segs) {
          const dur = s.ended_at ? Math.round((new Date(s.ended_at)-new Date(s.started_at))/1000) : Math.round((Date.now()-new Date(s.started_at))/1000);
          const m = Math.floor(dur/60), h = Math.floor(m/60);
          const d = h ? `${h}h ${m%60}m` : `${m}m`;
          console.log(`${s.ended_at ? "  " : "▶ "}${s.ticket_key}  ${d}  ${s.user_action || ""}${s.jira_comment_id ? "  💬" : ""}`);
        }
        console.log("");
      } else if (sub === "list") {
        console.log("▷ 현재 세션에 segment 없음.");
      }
      // 본인 미완료 티켓 추천
      const recos = await call("POST", "/api/sessions/recommendations", { branch: null, commits: [] }).catch(() => null);
      const open = recos?.assigned_open || [];
      if (open.length) {
        console.log(`▷ 본인 미완료 티켓 (top ${Math.min(open.length, 8)})`);
        for (const t of open.slice(0, 8)) {
          const status = t.status ? ` [${t.status}]` : "";
          const prio = t.priority ? ` (${t.priority})` : "";
          console.log(`  • ${t.key}${status}${prio}  ${(t.summary || "").slice(0, 60)}`);
        }
        console.log("");
        console.log("  ▶ 시작: /tracker-ticket start <KEY>");
      } else if (!recos?.has_jira) {
        console.log("(Jira 미연동 — /tracker-config 또는 프로필 페이지에서 연결)");
      } else {
        console.log("(본인에게 할당된 미완료 티켓 없음)");
      }
    } else if (sub === "done") {
      if (!sid) throw new Error("CLAUDE_SESSION_ID not set");
      const r = await call("POST", `/api/sessions/${encodeURIComponent(sid)}/writeback`, {});
      console.log(`✓ Jira writeback 완료 (${(r.results||[]).length}개 티켓)`);
      for (const x of (r.results || [])) {
        if (x.ok) console.log(`  ✓ ${x.ticket_key}  ${x.duration}  comment#${x.comment_id}`);
        else console.log(`  ✗ ${x.ticket_key}  ${x.error}`);
      }
      try {
        const w = await call("POST", `/api/sessions/${encodeURIComponent(sid)}/wiki-sync`, {});
        if (w.skipped) console.log(`(wiki-sync 건너뜀: ${w.skipped})`);
        else {
          console.log(`✓ Wiki 갱신 완료 (${(w.results||[]).length}개 페이지)`);
          for (const x of (w.results || [])) {
            const arrow = x.action === "created" ? "🆕" : "📝";
            if (x.ok) console.log(`  ${arrow} ${x.ticket_key}  ${x.page_url}`);
            else console.log(`  ✗ ${x.ticket_key}  ${x.error}`);
          }
        }
      } catch (e) { console.log(`(wiki-sync 실패: ${e.message})`); }
    } else if (sub === "wiki") {
      if (!sid) throw new Error("CLAUDE_SESSION_ID not set");
      const w = await call("POST", `/api/sessions/${encodeURIComponent(sid)}/wiki-sync`, {});
      if (w.skipped) console.log(`건너뜀: ${w.skipped}`);
      else {
        console.log(`✓ Wiki 갱신 (${(w.results||[]).length}개 페이지)`);
        for (const x of (w.results || [])) {
          const arrow = x.action === "created" ? "🆕 생성" : "📝 갱신";
          if (x.ok) console.log(`  ${arrow}  ${x.ticket_key}  ${x.page_url}`);
          else console.log(`  ✗ ${x.ticket_key}  ${x.error}`);
        }
      }
    } else {
      console.log("usage: /tracker-ticket <start|end|context|list|done> [KEY]");
      process.exit(2);
    }
  } catch (e) {
    console.error("error:", e.message || e);
    process.exit(1);
  }
})();
