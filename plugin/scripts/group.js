#!/usr/bin/env node
/**
 * /tracker-group <subcommand> ... — bundle multiple Claude Code sessions
 * (e.g. agent-team workers in different worktrees) into one logical task,
 * so cost/segments/writeback aggregate at the group level.
 *
 * Subcommands:
 *   start [name]           새 그룹 생성 + 현재 세션을 orchestrator로 등록
 *   attach <gid>           현재 세션을 기존 그룹에 attach (worker 역할)
 *   status [gid]           현재(또는 지정) 그룹 정보·멤버·티켓 출력
 *   list                   본인이 만든 그룹 목록
 *   ticket <KEY> [gid]     그룹 내 모든 세션에 티켓 segment 시작
 *   end [gid]              그룹 내 모든 열린 segment 종료
 *   done [gid]             writeback (그룹 전체 작업을 티켓당 댓글 1개로 합쳐 Jira 등록)
 *   close [gid]            그룹 종료 (이후 attach 차단)
 *
 * 자동 attach: spawn된 worker 프로세스에 CLAUDE_TRACKER_GROUP_ID env가 있으면
 *              hook.js의 session_start가 자동으로 attach 호출. 슬래시 커맨드 불필요.
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
  const endpoint = cfg.endpoint || process.env.CLAUDE_TRACKER_ENDPOINT || cfg.server;
  const token = cfg.token || process.env.CLAUDE_TRACKER_TOKEN;
  if (!endpoint || !token) throw new Error("tracker.json에 endpoint/token 없음 — /tracker-config 먼저 실행");
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

// Track "current group" client-side so subcommands without explicit gid know the target.
const STATE = path.join(os.homedir(), ".claude", "tracker-group-active");
function currentGroup() {
  if (process.env.CLAUDE_TRACKER_GROUP_ID) return process.env.CLAUDE_TRACKER_GROUP_ID;
  try { return fs.readFileSync(STATE, "utf8").trim() || ""; } catch { return ""; }
}
function setCurrentGroup(gid) {
  try { fs.writeFileSync(STATE, gid + "\n"); } catch {}
}
function clearCurrentGroup() {
  try { fs.unlinkSync(STATE); } catch {}
}

function fmtDur(sec) {
  sec = Math.max(0, Math.round(sec || 0));
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60);
  return h ? `${h}h ${m}m` : `${m}m`;
}
function shortSid(s) { return (s || "").length > 12 ? s.slice(0, 8) + "…" + s.slice(-4) : s; }

function fmtGroup(g) {
  const lines = [];
  lines.push(`🧩 ${g.name || "(이름 없음)"}  ${g.id}`);
  lines.push(`   owner: ${g.owner_email}${g.team ? "  team: " + g.team : ""}  생성: ${(g.created_at || "").slice(0, 16).replace("T", " ")}${g.closed_at ? "  [closed]" : ""}`);
  if ((g.members || []).length) {
    lines.push("");
    lines.push(`▷ 세션 (${g.members.length}개)`);
    for (const m of g.members) {
      const tail = (m.cwd || "").split("/").slice(-2).join("/");
      lines.push(`  ${m.role === "orchestrator" ? "★" : "·"} ${shortSid(m.session_id)}  ${m.role || "?"}  ${tail}  events=${m.events || 0}  tokens=${m.tokens || 0}`);
    }
  }
  if ((g.tickets || []).length) {
    lines.push("");
    lines.push(`▷ 티켓 (${g.tickets.length}개)`);
    for (const t of g.tickets) {
      lines.push(`  ${t.ticket_key}  sessions=${t.sessions}  segs=${t.segments}  time=${fmtDur(t.sec)}`);
    }
  }
  if ((g.writeback_comments || []).length) {
    lines.push("");
    lines.push(`▷ writeback (${g.writeback_comments.length}건)`);
    for (const c of g.writeback_comments) {
      lines.push(`  ${c.ticket_key}  comment#${c.jira_comment_id}  ${(c.posted_at || "").slice(0, 16).replace("T", " ")}`);
    }
  }
  return lines.join("\n");
}

(async () => {
  const sub = process.argv[2];
  const arg = process.argv[3];
  const arg2 = process.argv[4];
  const sid = sessionId();
  try {
    if (!sub || sub === "help") {
      console.log("usage: /tracker-group <start|attach|status|list|ticket|end|done|close>");
      console.log("");
      console.log("  start [name]            새 그룹 + 현재 세션 등록 (orchestrator)");
      console.log("  attach <gid>            현재 세션을 기존 그룹에 worker로 등록");
      console.log("  status [gid]            현재(또는 지정) 그룹 상세");
      console.log("  list                    본인 그룹 목록");
      console.log("  ticket <KEY> [gid]      그룹 모든 세션에 티켓 segment 시작");
      console.log("  end [gid]               열린 segment 모두 종료");
      console.log("  done [gid]              writeback (티켓당 댓글 1개로 합쳐 Jira 등록)");
      console.log("  close [gid]             그룹 종료");
      return;
    }

    if (sub === "start") {
      const name = arg || `task-${new Date().toISOString().slice(0, 16).replace("T", " ")}`;
      const r = await call("POST", "/api/groups", { name, session_id: sid || undefined, role: sid ? "orchestrator" : undefined });
      setCurrentGroup(r.group_id);
      console.log(`✓ 그룹 생성: ${r.group_id}  "${name}"`);
      if (sid) console.log(`  현재 세션을 orchestrator로 등록`);
      console.log("");
      console.log("▶ Worker 프로세스에 다음을 export 하세요 (현재 셸 + 자식 프로세스에 전파):");
      console.log("");
      console.log(`  export CLAUDE_TRACKER_GROUP_ID=${r.group_id}`);
      console.log("");
      console.log("그 셸에서 spawn된 모든 Claude Code worker가 SessionStart에 자동 attach 됩니다.");
      console.log("그룹 보기: /tracker-group status");
      return;
    }

    if (sub === "attach") {
      if (!arg) throw new Error("usage: /tracker-group attach <gid>");
      if (!sid) throw new Error("CLAUDE_SESSION_ID not set — Claude Code 안에서 실행하세요");
      const r = await call("POST", `/api/groups/${encodeURIComponent(arg)}/attach`, { session_id: sid, role: "worker" });
      setCurrentGroup(arg);
      console.log(`✓ 세션 ${shortSid(sid)} → 그룹 ${arg} 에 worker로 attach`);
      return;
    }

    if (sub === "status") {
      const gid = arg || currentGroup();
      if (!gid) throw new Error("그룹 미지정 — /tracker-group start 또는 status <gid>");
      const r = await call("GET", `/api/groups/${encodeURIComponent(gid)}`);
      console.log(fmtGroup(r));
      return;
    }

    if (sub === "list") {
      const r = await call("GET", "/api/groups?limit=20");
      if (!r.length) { console.log("(그룹 없음)"); return; }
      for (const g of r) {
        const stamp = (g.created_at || "").slice(0, 16).replace("T", " ");
        console.log(`  ${g.closed_at ? "✗" : "▸"} ${g.id}  members=${g.member_count}  ${stamp}  ${g.name || ""}`);
      }
      return;
    }

    if (sub === "ticket") {
      if (!arg) throw new Error("usage: /tracker-group ticket <KEY> [gid]");
      const gid = arg2 || currentGroup();
      if (!gid) throw new Error("그룹 미지정 — /tracker-group start 또는 ticket <KEY> <gid>");
      const r = await call("POST", `/api/groups/${encodeURIComponent(gid)}/segments/start`, { ticket_key: arg.toUpperCase() });
      console.log(`✓ ${r.ticket_key} segment 시작 — ${r.sessions}개 세션에 동시 적용 (${(r.started_at||"").replace("T", " ").replace(/\..+$/, "")})`);
      return;
    }

    if (sub === "end") {
      const gid = arg || currentGroup();
      if (!gid) throw new Error("그룹 미지정");
      const r = await call("POST", `/api/groups/${encodeURIComponent(gid)}/segments/end`, {});
      console.log(`✓ ${r.closed}개 segment 종료`);
      return;
    }

    if (sub === "done") {
      const gid = arg || currentGroup();
      if (!gid) throw new Error("그룹 미지정");
      const r = await call("POST", `/api/groups/${encodeURIComponent(gid)}/writeback`, {});
      console.log(`✓ writeback 완료 (${(r.results || []).length}개 티켓)`);
      for (const x of (r.results || [])) {
        if (x.ok) console.log(`  ✓ ${x.ticket_key}  ${x.total_duration}  sessions=${x.sessions}  comment#${x.comment_id}`);
        else      console.log(`  ✗ ${x.ticket_key}  ${x.error}`);
      }
      return;
    }

    if (sub === "close") {
      const gid = arg || currentGroup();
      if (!gid) throw new Error("그룹 미지정");
      await call("POST", `/api/groups/${encodeURIComponent(gid)}/close`, {});
      if (gid === currentGroup()) clearCurrentGroup();
      console.log(`✓ 그룹 ${gid} 종료`);
      return;
    }

    console.log("unknown subcommand: " + sub);
    process.exit(2);
  } catch (e) {
    console.error("error:", e.message || e);
    process.exit(1);
  }
})();
