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

  // Always exit 0 — never block the session
  process.exit(0);
})();
