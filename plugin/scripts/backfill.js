#!/usr/bin/env node
/**
 * Backfill events + messages from ~/.claude/projects/ transcripts.
 * Usage: node backfill.js [endpoint] [token]
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const https = require("https");

const ENDPOINT = process.argv[2] || process.env.CLAUDE_TRACKER_ENDPOINT || "http://localhost:3737/events";
const TOKEN = process.argv[3] || process.env.CLAUDE_TRACKER_TOKEN || null;
const BASE = ENDPOINT.replace(/\/events\/?$/, "").replace(/\/$/, "");
const MSG_URL = `${BASE}/messages/bulk`;
const USER_EMAIL = process.env.CLAUDE_TRACKER_USER || os.userInfo().username;
const USER_NAME = process.env.CLAUDE_TRACKER_NAME || null;
const TEAM = process.env.CLAUDE_TRACKER_TEAM || null;
const DEPT = process.env.CLAUDE_TRACKER_DEPARTMENT || null;
const ROOT = path.join(os.homedir(), ".claude", "projects");

function walk(dir, out = []) {
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name);
    const st = fs.statSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (p.endsWith(".jsonl")) out.push(p);
  }
  return out;
}

function postRaw(url, body) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const lib = u.protocol === "https:" ? https : http;
    const payload = Buffer.from(JSON.stringify(body));
    const req = lib.request(
      { method: "POST", hostname: u.hostname, port: u.port,
        path: u.pathname, timeout: 10000,
        headers: { "Content-Type": "application/json", "Content-Length": payload.length,
          ...(TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}) } },
      (res) => { res.on("data", () => {}); res.on("end", () => resolve(res.statusCode)); }
    );
    req.on("error", () => resolve(0));
    req.on("timeout", () => { req.destroy(); resolve(0); });
    req.write(payload); req.end();
  });
}

async function batch(url, items, concurrency, wrap = (x) => x) {
  let i = 0, ok = 0, fail = 0;
  const total = items.length;
  const start = Date.now();
  const label = url.split("/").pop();
  const tick = setInterval(() => {
    const pct = Math.round((i / Math.max(1,total)) * 100);
    const elapsed = Math.round((Date.now() - start) / 1000);
    const rate = i / Math.max(1, elapsed);
    const eta = rate > 0 ? Math.round((total - i) / rate) : 0;
    process.stdout.write(`  ${label} ${i}/${total} (${pct}%, ok=${ok} fail=${fail}, ${elapsed}s elapsed, ~${eta}s remaining)\n`);
  }, 5000);
  async function worker() {
    while (i < items.length) {
      const me = i++;
      const code = await postRaw(url, wrap(items[me]));
      if (code && code < 300) ok++; else fail++;
    }
  }
  try { await Promise.all(Array.from({ length: concurrency }, worker)); } finally { clearInterval(tick); }
  process.stdout.write(`  ${label} done: ${total}/${total} ok=${ok} fail=${fail} in ${Math.round((Date.now()-start)/1000)}s\n`);
  return { ok, fail };
}

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

(async () => {
  if (!fs.existsSync(ROOT)) { console.error("No ~/.claude/projects"); process.exit(1); }
  const files = walk(ROOT);
  console.log(`Scanning ${files.length} transcript files…`);

  const events = [];
  const messages = [];
  const userBlock = { email: USER_EMAIL, name: USER_NAME, team: TEAM, department: DEPT,
    host: os.hostname(), platform: `${os.platform()} ${os.release()}` };

  for (const f of files) {
    const sessionId = path.basename(f, ".jsonl");
    const projDir = path.basename(path.dirname(f));
    const cwd = projDir.startsWith("-") ? projDir.replace(/-/g, "/") : projDir;
    let raw; try { raw = fs.readFileSync(f, "utf8"); } catch { continue; }
    // /rename으로 설정된 customTitle 추출 (마지막 등장)
    let customTitle = null;
    for (const ln of raw.split("\n").reverse()) {
      if (!ln) continue;
      try { const o = JSON.parse(ln); if (o.type === "custom-title" && o.customTitle) { customTitle = String(o.customTitle); break; } } catch {}
    }
    if (customTitle) {
      events.push({
        event: "rename", ts: new Date().toISOString(),
        session_id: sessionId, user: userBlock, cwd,
        custom_title: customTitle,
        hook_payload: { source: "backfill-rename" },
      });
    }
    let seq = 0;
    for (const line of raw.split("\n")) {
      if (!line) continue;
      let obj; try { obj = JSON.parse(line); } catch { continue; }
      if (obj.type !== "user" && obj.type !== "assistant") continue;
      const ts = obj.timestamp || new Date().toISOString();
      const msg = obj.message || {};
      const model = msg.model || null;
      const usage = msg.usage || null;
      const flat = flattenContent(msg.content);

      messages.push({
        session_id: sessionId, seq: seq++, ts, role: obj.type,
        user_email: USER_EMAIL, team: TEAM, cwd, model,
        text: flat.text, thinking: flat.thinking,
        tool_calls: flat.tool_calls.length ? flat.tool_calls : null,
        tool_result: flat.tool_result,
        input_tokens: usage?.input_tokens || 0,
        output_tokens: usage?.output_tokens || 0,
        cache_read_tokens: usage?.cache_read_input_tokens || 0,
        cache_create_tokens: usage?.cache_creation_input_tokens || 0,
      });

      if (obj.type === "assistant" && usage) {
        events.push({
          event: "stop", ts, session_id: sessionId, user: userBlock, cwd, model,
          usage: {
            input_tokens: usage.input_tokens || 0,
            output_tokens: usage.output_tokens || 0,
            cache_read_input_tokens: usage.cache_read_input_tokens || 0,
            cache_creation_input_tokens: usage.cache_creation_input_tokens || 0,
          },
          hook_payload: { source: "backfill" },
        });
        for (const tc of flat.tool_calls) {
          events.push({
            event: "pre_tool", ts, session_id: sessionId, user: userBlock, cwd, model,
            hook_payload: { tool_name: tc.name, source: "backfill" },
          });
        }
      }
    }
  }

  console.log(`Built ${events.length} events, ${messages.length} messages.`);

  console.log(`Posting events → ${ENDPOINT}`);
  const e = await batch(ENDPOINT, events, 16);
  console.log(`\n  events ok=${e.ok} fail=${e.fail}`);

  console.log(`Posting messages → ${MSG_URL} (chunked)`);
  const chunks = [];
  for (let i = 0; i < messages.length; i += 200) chunks.push(messages.slice(i, i + 200));
  const m = await batch(MSG_URL, chunks, 8, (chunk) => ({ messages: chunk }));
  console.log(`\n  message-batches ok=${m.ok} fail=${m.fail} (${messages.length} rows total)`);
})();
