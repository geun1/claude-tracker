#!/usr/bin/env node
/**
 * Aggregate local tracker logs (~/.claude/tracker-logs/*.jsonl) for the last N days.
 * Also hits <endpoint>/stats?days=N if configured.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const https = require("https");

const DAYS = parseInt(process.argv[2] || "7", 10);

function loadConfig() {
  const p = path.join(os.homedir(), ".claude", "tracker.json");
  try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return {}; }
}

function readLocal(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  const cutoff = Date.now() - DAYS * 86400_000;
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".jsonl"))) {
    for (const line of fs.readFileSync(path.join(dir, f), "utf8").split("\n")) {
      if (!line) continue;
      try {
        const o = JSON.parse(line);
        if (new Date(o.ts).getTime() >= cutoff) out.push(o);
      } catch {}
    }
  }
  return out;
}

function aggregate(events) {
  const sessions = new Set();
  const byModel = {};
  const byTool = {};
  const byCwd = {};
  let inputTokens = 0, outputTokens = 0, cacheRead = 0, cacheCreate = 0;
  for (const e of events) {
    if (e.session_id) sessions.add(e.session_id);
    if (e.model) byModel[e.model] = (byModel[e.model] || 0) + 1;
    if (e.cwd) byCwd[e.cwd] = (byCwd[e.cwd] || 0) + 1;
    const toolName = e.hook_payload?.tool_name;
    if (toolName && e.event === "pre_tool") byTool[toolName] = (byTool[toolName] || 0) + 1;
    const u = e.usage;
    if (u) {
      inputTokens += u.input_tokens || 0;
      outputTokens += u.output_tokens || 0;
      cacheRead += u.cache_read_input_tokens || 0;
      cacheCreate += u.cache_creation_input_tokens || 0;
    }
  }
  return {
    days: DAYS,
    events: events.length,
    sessions: sessions.size,
    tokens: { input: inputTokens, output: outputTokens, cache_read: cacheRead, cache_create: cacheCreate },
    byModel,
    topTools: Object.entries(byTool).sort((a, b) => b[1] - a[1]).slice(0, 10),
    topCwds: Object.entries(byCwd).sort((a, b) => b[1] - a[1]).slice(0, 10),
  };
}

function fetchRemote(endpoint, token) {
  return new Promise((resolve) => {
    try {
      // endpoint points at /events; strip the trailing path to get the server base
      const base = endpoint.replace(/\/events\/?$/, "").replace(/\/$/, "");
      const url = new URL(`${base}/stats?days=${DAYS}`);
      const lib = url.protocol === "https:" ? https : http;
      const req = lib.request(
        { method: "GET", hostname: url.hostname, port: url.port, path: url.pathname + url.search,
          headers: token ? { Authorization: `Bearer ${token}` } : {}, timeout: 2000 },
        (res) => { let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } }); }
      );
      req.on("error", () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
      req.end();
    } catch { resolve(null); }
  });
}

(async () => {
  const cfg = loadConfig();
  const dir = cfg.local_log_dir || path.join(os.homedir(), ".claude", "tracker-logs");
  const local = aggregate(readLocal(dir));
  console.log("=== Local logs ===");
  console.log(JSON.stringify(local, null, 2));
  if (cfg.endpoint) {
    const remote = await fetchRemote(cfg.endpoint, cfg.token);
    console.log("\n=== Remote server ===");
    console.log(remote ? JSON.stringify(remote, null, 2) : "(server unreachable)");
  }
})();
