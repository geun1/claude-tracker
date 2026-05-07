#!/usr/bin/env node
/**
 * Single hook entry. Reads JSON payload on stdin, enriches with env/config,
 * ships to the tracker server. Fails silently to never block Claude Code.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const https = require("https");

const EVENT = process.argv[2] || "unknown";

function loadConfig() {
  const candidates = [
    process.env.CLAUDE_TRACKER_CONFIG,
    path.join(os.homedir(), ".claude", "tracker.json"),
    path.join(os.homedir(), ".config", "claude-tracker", "config.json"),
  ].filter(Boolean);
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf8"));
    } catch {}
  }
  return {};
}

function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    if (process.stdin.isTTY) return resolve({});
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (data += c));
    process.stdin.on("end", () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        resolve({ _raw: data.slice(0, 4000) });
      }
    });
    setTimeout(() => resolve({}), 1500);
  });
}

// Anthropic 메시지 content (배열) → flat {text, thinking, tool_calls, tool_result}
function flattenContent(content) {
  if (typeof content === "string") return { text: content, thinking: null, tool_calls: [], tool_result: null };
  const out = { text: "", thinking: "", tool_calls: [], tool_result: null };
  if (!Array.isArray(content)) return out;
  for (const c of content) {
    if (!c) continue;
    if (c.type === "text") out.text += (c.text || "");
    else if (c.type === "thinking") out.thinking += (c.thinking || "");
    else if (c.type === "tool_use") out.tool_calls.push({ id: c.id, name: c.name, input: c.input });
    else if (c.type === "tool_result") {
      let txt = c.content;
      if (Array.isArray(txt)) txt = txt.map((p) => p.text || JSON.stringify(p)).join("\n");
      out.tool_result = { tool_use_id: c.tool_use_id, output: typeof txt === "string" ? txt : JSON.stringify(txt), is_error: !!c.is_error };
    }
  }
  return { text: out.text || null, thinking: out.thinking || null, tool_calls: out.tool_calls, tool_result: out.tool_result };
}

// cwd에서 git 컨텍스트 수집 (3초 timeout)
function collectGitContext(cwd) {
  const { execSync } = require("child_process");
  if (!cwd || !fs.existsSync(cwd)) return null;
  try {
    const opts = { cwd, encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"] };
    const isRepo = execSync("git rev-parse --is-inside-work-tree", opts).trim() === "true";
    if (!isRepo) return null;
    const repoRoot = execSync("git rev-parse --show-toplevel", opts).trim();
    let remote = ""; try { remote = execSync("git remote get-url origin", opts).trim(); } catch {}
    let branch = ""; try { branch = execSync("git rev-parse --abbrev-ref HEAD", opts).trim(); } catch {}
    let commits = [];
    try {
      const log = execSync('git log --since="6 hours ago" --pretty=format:"%H|%s|%ct" -n 20', opts);
      commits = log.split("\n").filter(Boolean).map(l => {
        const [sha, msg, ts] = l.split("|");
        return { sha: sha?.slice(0, 12), msg, ts: ts ? new Date(parseInt(ts) * 1000).toISOString() : null };
      });
    } catch {}
    let diffStat = ""; try { diffStat = execSync('git diff --shortstat HEAD~10..HEAD 2>/dev/null', opts).trim(); } catch {}
    return { repo_root: repoRoot, remote_url: remote || null, branch: branch || null, commits, diff_stat: diffStat || null };
  } catch { return null; }
}

// transcript 전체를 messages bulk 형식으로 변환
function buildMessagesFromTranscript(transcriptPath, sessionId, userBlock, cwd) {
  if (!transcriptPath || !fs.existsSync(transcriptPath)) return [];
  let raw; try { raw = fs.readFileSync(transcriptPath, "utf8"); } catch { return []; }
  const out = [];
  let seq = 0;
  for (const line of raw.split("\n")) {
    if (!line) continue;
    let obj; try { obj = JSON.parse(line); } catch { continue; }
    if (obj.type !== "user" && obj.type !== "assistant") continue;
    const ts = obj.timestamp || new Date().toISOString();
    const msg = obj.message || {};
    const usage = msg.usage || null;
    const flat = flattenContent(msg.content);
    out.push({
      session_id: sessionId, seq: seq++, ts, role: obj.type,
      user_email: userBlock.email, team: userBlock.team, cwd, model: msg.model || null,
      text: flat.text, thinking: flat.thinking,
      tool_calls: flat.tool_calls.length ? flat.tool_calls : null,
      tool_result: flat.tool_result,
      input_tokens: usage?.input_tokens || 0,
      output_tokens: usage?.output_tokens || 0,
      cache_read_tokens: usage?.cache_read_input_tokens || 0,
      cache_create_tokens: usage?.cache_creation_input_tokens || 0,
    });
  }
  return out;
}

// Claude Code의 /rename은 transcript에 {type:"custom-title"} 라인을 남김.
function extractCustomTitle(transcriptPath) {
  if (!transcriptPath || !fs.existsSync(transcriptPath)) return null;
  try {
    const lines = fs.readFileSync(transcriptPath, "utf8").trim().split("\n");
    for (let i = lines.length - 1; i >= 0; i--) {
      try {
        const o = JSON.parse(lines[i]);
        if (o.type === "custom-title" && o.customTitle) return String(o.customTitle);
      } catch {}
    }
  } catch {}
  return null;
}

function readTranscriptTail(transcriptPath) {
  if (!transcriptPath || !fs.existsSync(transcriptPath)) return null;
  try {
    const raw = fs.readFileSync(transcriptPath, "utf8");
    const lines = raw.trim().split("\n").filter(Boolean);
    const tail = lines.slice(-25).map((l) => {
      try { return JSON.parse(l); } catch { return null; }
    }).filter(Boolean);
    // Extract latest usage block (Anthropic API usage keys)
    let usage = null, model = null;
    for (let i = tail.length - 1; i >= 0; i--) {
      const msg = tail[i]?.message || tail[i];
      if (msg?.usage) { usage = msg.usage; model = msg.model || null; break; }
    }
    return { usage, model, lineCount: lines.length };
  } catch {
    return null;
  }
}

function post(endpoint, token, body) {
  return new Promise((resolve) => {
    try {
      const url = new URL(endpoint);
      const lib = url.protocol === "https:" ? https : http;
      const payload = Buffer.from(JSON.stringify(body));
      const req = lib.request(
        {
          method: "POST",
          hostname: url.hostname,
          port: url.port || (url.protocol === "https:" ? 443 : 80),
          path: url.pathname + (url.search || ""),
          headers: {
            "Content-Type": "application/json",
            "Content-Length": payload.length,
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
          timeout: 2000,
        },
        (res) => { res.on("data", () => {}); res.on("end", () => resolve(true)); }
      );
      req.on("error", () => resolve(false));
      req.on("timeout", () => { req.destroy(); resolve(false); });
      req.write(payload);
      req.end();
    } catch {
      resolve(false);
    }
  });
}

// post() 와 동일하지만 응답 JSON을 파싱해 반환 (실패 시 null). 추천/조회용.
function postJson(endpoint, token, body, timeoutMs) {
  return new Promise((resolve) => {
    try {
      const url = new URL(endpoint);
      const lib = url.protocol === "https:" ? https : http;
      const payload = Buffer.from(JSON.stringify(body));
      const req = lib.request(
        {
          method: "POST",
          hostname: url.hostname,
          port: url.port || (url.protocol === "https:" ? 443 : 80),
          path: url.pathname + (url.search || ""),
          headers: {
            "Content-Type": "application/json",
            "Content-Length": payload.length,
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
          timeout: Math.max(500, timeoutMs || 4000),
        },
        (res) => {
          let buf = "";
          res.on("data", (c) => { buf += c.toString("utf8"); });
          res.on("end", () => { try { resolve(JSON.parse(buf)); } catch { resolve(null); } });
        }
      );
      req.on("error", () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
      req.write(payload);
      req.end();
    } catch { resolve(null); }
  });
}

function appendLocal(logDir, body) {
  try {
    fs.mkdirSync(logDir, { recursive: true });
    const f = path.join(logDir, `${new Date().toISOString().slice(0, 10)}.jsonl`);
    fs.appendFileSync(f, JSON.stringify(body) + "\n");
  } catch {}
}

(async () => {
  const cfg = loadConfig();
  const input = await readStdin();

  // Only attach usage on turn-boundary events — otherwise every PreToolUse
  // would re-report the same usage block and inflate totals.
  // Only `stop` fires per assistant turn with a fresh usage block. Any other
  // event (including session_end) would just re-read the same latest block.
  const USAGE_EVENTS = new Set(["stop"]);
  const transcriptInfo = USAGE_EVENTS.has(EVENT)
    ? readTranscriptTail(input.transcript_path)
    : (() => {
        const t = readTranscriptTail(input.transcript_path);
        return t ? { model: t.model, usage: null, lineCount: t.lineCount } : null;
      })();

  const body = {
    event: EVENT,
    ts: new Date().toISOString(),
    user: {
      email:      cfg.user_email      || process.env.CLAUDE_TRACKER_USER       || os.userInfo().username,
      name:       cfg.user_name       || process.env.CLAUDE_TRACKER_NAME       || null,
      team:       cfg.team            || process.env.CLAUDE_TRACKER_TEAM       || null,
      department: cfg.department      || process.env.CLAUDE_TRACKER_DEPARTMENT || null,
      host: os.hostname(),
      platform: `${os.platform()} ${os.release()}`,
    },
    session_id: input.session_id || null,
    cwd: input.cwd || process.cwd(),
    model: transcriptInfo?.model || input.model || null,
    usage: transcriptInfo?.usage || null,
    transcript_lines: transcriptInfo?.lineCount || null,
    custom_title: extractCustomTitle(input.transcript_path),
    hook_payload: input,
    config_snapshot: cfg.include_config === false ? null : {
      permission_mode: input.permission_mode || null,
    },
  };

  const logDir = cfg.local_log_dir || path.join(os.homedir(), ".claude", "tracker-logs");
  appendLocal(logDir, body);

  // Persist current session_id per-cwd for slash commands like /tracker-ticket.
  // Key: cwd → session_id. Pick most-recent by mtime.
  if (input.session_id) {
    try {
      const dir = path.join(os.homedir(), ".claude", "tracker-sessions");
      fs.mkdirSync(dir, { recursive: true });
      const safeKey = (input.cwd || process.cwd()).replace(/[^a-zA-Z0-9._-]/g, "_").slice(-100);
      fs.writeFileSync(path.join(dir, safeKey), input.session_id);
      // also write a "latest" pointer
      fs.writeFileSync(path.join(dir, ".latest"), JSON.stringify({ session_id: input.session_id, cwd: input.cwd || process.cwd(), ts: Date.now() }));
    } catch {}
  }

  // Zero-config default: if the user never ran /tracker-config, still try to
  // reach a locally-running tracker server. Silently no-ops if nothing listens.
  const endpoint =
    cfg.endpoint ||
    process.env.CLAUDE_TRACKER_ENDPOINT ||
    "http://localhost:3737/events";
  await post(endpoint, cfg.token || process.env.CLAUDE_TRACKER_TOKEN, body);

  // ── session_start: CLAUDE_TRACKER_GROUP_ID 가 있으면 그룹에 자동 attach ──
  if (EVENT === "session_start" && input.session_id && process.env.CLAUDE_TRACKER_GROUP_ID) {
    try {
      const base = endpoint.replace(/\/events\/?$/, "");
      const gid = process.env.CLAUDE_TRACKER_GROUP_ID;
      const role = process.env.CLAUDE_TRACKER_GROUP_ROLE || "worker";
      await postJson(`${base}/api/groups/${encodeURIComponent(gid)}/attach`,
        cfg.token || process.env.CLAUDE_TRACKER_TOKEN,
        { session_id: input.session_id, role },
        3000
      );
    } catch {}
  }

  // ── session_start: 브랜치/커밋 → 티켓 추천을 stderr로 안내 ──────────
  if (EVENT === "session_start" && input.session_id) {
    try {
      const git = collectGitContext(input.cwd || body.cwd);
      const base = endpoint.replace(/\/events\/?$/, "");
      const recos = await postJson(`${base}/api/sessions/recommendations`,
        cfg.token || process.env.CLAUDE_TRACKER_TOKEN,
        {
          session_id: input.session_id,
          branch: git?.branch || null,
          remote_url: git?.remote_url || null,
          repo_root: git?.repo_root || null,
          commits: (git?.commits || []).map((c) => c.msg).filter(Boolean).slice(0, 10),
          cwd: input.cwd || body.cwd || null,
        },
        4000
      );
      // 1) 자동 그룹 합류 (ticket 감지보다 우선) — 같은 (user, repo)의 active 그룹에 자동 attach 됐다면 안내.
      // 2) 그 외 브랜치/커밋에서 감지된 티켓 안내.
      const lines = [];
      if (recos?.auto_group) {
        lines.push("");
        lines.push("[claude-tracker] 자동 그룹 합류");
        const ag = recos.auto_group;
        const tag = ag.auto_attached ? "🆕 합류" : "▸ 기존 멤버";
        lines.push(`  ${tag}: ${ag.name}  (${ag.id})`);
        if (ag.active_ticket_key) {
          lines.push(`  🎟  활성 티켓: ${ag.active_ticket_key}  ← 이 세션에 segment 자동 시작됨`);
        }
        lines.push(`  보기: ${endpoint.replace(/\/events\/?$/, "")}/g/${ag.id}`);
        lines.push("");
      }
      if (recos && recos.detected?.length && !recos.auto_group?.active_ticket_key) {
        lines.push("[claude-tracker] 티켓 추천");
        if (git?.branch || git?.remote_url) {
          const repo = (git.remote_url || "").replace(/^https?:\/\/[^/]+\//, "").replace(/\.git$/, "");
          lines.push(`  📂 ${repo || "(remote 없음)"}  ·  브랜치: ${git.branch || "-"}`);
        }
        lines.push("  🎯 감지된 티켓:");
        for (const d of recos.detected.slice(0, 5)) {
          const star = d.in_assigned ? "★ " : "  ";
          const status = d.status ? ` [${d.status}]` : "";
          const summary = d.summary ? `  ${d.summary.slice(0, 60)}` : "";
          lines.push(`    ${star}${d.key}${status}${summary}`);
          lines.push(`        근거: ${d.evidence}`);
        }
        lines.push("");
        lines.push(`  ▶ 시작: /tracker-ticket start ${recos.detected[0].key}`);
        lines.push("");
      }
      if (lines.length) {
        const banner = lines.join("\n");
        // 1) LLM 컨텍스트로 주입 (Claude가 첫 응답 때 활용 가능)
        process.stdout.write(JSON.stringify({
          hookSpecificOutput: {
            hookEventName: "SessionStart",
            additionalContext: banner,
          },
        }) + "\n");
        // 2) 사용자 터미널에 직접 노출 (stdout/stderr는 Claude Code가 capture하므로 /dev/tty로 우회)
        try {
          fs.writeFileSync("/dev/tty", banner + "\n");
        } catch { /* /dev/tty 접근 불가 환경(SSH, daemon 등)은 silent */ }
      }
    } catch {}
  }

  // Stop / SessionEnd 이벤트에서는 transcript 본문을 messages 테이블로도 동기화
  // (UNIQUE(session_id, seq) 덕에 INSERT OR REPLACE이라 중복 안전)
  if ((EVENT === "stop" || EVENT === "session_end") && input.transcript_path && input.session_id) {
    const msgs = buildMessagesFromTranscript(input.transcript_path, input.session_id, body.user, body.cwd);
    if (msgs.length) {
      const base = endpoint.replace(/\/events\/?$/, "");
      const bulkUrl = `${base}/messages/bulk`;
      // 200건씩 청크로 보냄
      for (let i = 0; i < msgs.length; i += 200) {
        await post(bulkUrl, cfg.token || process.env.CLAUDE_TRACKER_TOKEN, { messages: msgs.slice(i, i + 200) });
      }
    }
    // git 컨텍스트도 push
    const git = collectGitContext(input.cwd || body.cwd);
    if (git) {
      const base = endpoint.replace(/\/events\/?$/, "");
      await post(`${base}/api/session-git`, cfg.token || process.env.CLAUDE_TRACKER_TOKEN, {
        session_id: input.session_id, ...git,
      });
    }
  }

  // Always exit 0 — never block the session
  process.exit(0);
})();
