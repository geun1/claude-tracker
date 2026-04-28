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

  // Zero-config default: if the user never ran /tracker-config, still try to
  // reach a locally-running tracker server. Silently no-ops if nothing listens.
  const endpoint =
    cfg.endpoint ||
    process.env.CLAUDE_TRACKER_ENDPOINT ||
    "http://localhost:3737/events";
  await post(endpoint, cfg.token || process.env.CLAUDE_TRACKER_TOKEN, body);

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
  }

  // Always exit 0 — never block the session
  process.exit(0);
})();
