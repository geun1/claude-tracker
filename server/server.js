#!/usr/bin/env node
/**
 * claude-tracker receiver — multi-tenant edition.
 *
 *   POST /events       -> ingest a hook event
 *   GET  /stats        -> aggregated stats (filter ?team= ?user=)
 *   GET  /timeseries   -> daily series
 *   GET  /sessions     -> recent sessions
 *   GET  /events       -> raw events
 *   GET  /users        -> user leaderboard with team
 *   GET  /teams        -> team rollup with cost
 *   GET  /cost         -> total cost ($) by model/team/user
 *   GET  /export.csv   -> CSV download
 *   GET  /health
 *   GET  /             -> dashboard
 *
 * Env:
 *   PORT=3737
 *   TRACKER_TOKEN=...   (Bearer-required if set)
 *   TRACKER_DB=./tracker.db
 *   PRICING_FILE=./pricing.json   (model -> {input, output, cache_read, cache_create} per 1M)
 */
const express = require("express");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const PORT = parseInt(process.env.PORT || "3737", 10);
const TOKEN = process.env.TRACKER_TOKEN || null;
const DB_PATH = process.env.TRACKER_DB || path.join(__dirname, "tracker.db");
const PRICING_PATH = process.env.PRICING_FILE || path.join(__dirname, "pricing.json");

// ── Pricing ────────────────────────────────────────────────────────────────
// Per 1M tokens (USD). Override with PRICING_FILE if your contract differs.
const DEFAULT_PRICING = {
  "claude-opus-4-7":           { input: 15, output: 75, cache_read: 1.5,  cache_create: 18.75 },
  "claude-opus-4-6":           { input: 15, output: 75, cache_read: 1.5,  cache_create: 18.75 },
  "claude-sonnet-4-6":         { input: 3,  output: 15, cache_read: 0.3,  cache_create: 3.75  },
  "claude-haiku-4-5-20251001": { input: 1,  output: 5,  cache_read: 0.1,  cache_create: 1.25  },
  "default":                   { input: 3,  output: 15, cache_read: 0.3,  cache_create: 3.75  },
};
let PRICING = DEFAULT_PRICING;
try { if (fs.existsSync(PRICING_PATH)) PRICING = { ...DEFAULT_PRICING, ...JSON.parse(fs.readFileSync(PRICING_PATH, "utf8")) }; } catch {}

function priceOf(model) { return PRICING[model] || PRICING.default; }
function cost(row) {
  const p = priceOf(row.model);
  return (
    ((row.input_tokens   || 0) * p.input        / 1e6) +
    ((row.output_tokens  || 0) * p.output       / 1e6) +
    ((row.cache_read_tokens   || 0) * p.cache_read   / 1e6) +
    ((row.cache_create_tokens || 0) * p.cache_create / 1e6)
  );
}

// ── DB ─────────────────────────────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
// Capture client IP/UA on each event so we can show machine + location.
const expressTrustProxy = true;
db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    ts TEXT NOT NULL,
    role TEXT NOT NULL,            -- user | assistant | tool_result | system
    user_email TEXT,
    team TEXT,
    cwd TEXT,
    model TEXT,
    text TEXT,                     -- flattened user/assistant text
    thinking TEXT,                 -- assistant thinking blocks
    tool_calls_json TEXT,          -- [{name, input, id}]
    tool_result_json TEXT,         -- {tool_use_id, output, is_error}
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    cache_read_tokens INTEGER DEFAULT 0,
    cache_create_tokens INTEGER DEFAULT 0,
    UNIQUE(session_id, seq)
  );
  CREATE INDEX IF NOT EXISTS idx_msg_session ON messages(session_id, seq);
  CREATE INDEX IF NOT EXISTS idx_msg_user ON messages(user_email);
  CREATE INDEX IF NOT EXISTS idx_msg_ts ON messages(ts);

  CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    event TEXT NOT NULL,
    session_id TEXT,
    user_email TEXT,
    user_name TEXT,
    team TEXT,
    department TEXT,
    host TEXT,
    platform TEXT,
    cwd TEXT,
    model TEXT,
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    cache_read_tokens INTEGER DEFAULT 0,
    cache_create_tokens INTEGER DEFAULT 0,
    tool_name TEXT,
    payload_json TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
  CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
  CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_email);
  CREATE INDEX IF NOT EXISTS idx_events_team ON events(team);
  CREATE INDEX IF NOT EXISTS idx_events_user_ts ON events(user_email, ts DESC);
  CREATE INDEX IF NOT EXISTS idx_events_session_ts ON events(session_id, ts);
`);

// Migrate older DBs that lack the new columns.
const cols = new Set(db.prepare("PRAGMA table_info(events)").all().map((c) => c.name));
for (const col of ["user_name", "team", "department", "client_ip", "client_city", "client_country", "user_agent"]) {
  if (!cols.has(col)) db.exec(`ALTER TABLE events ADD COLUMN ${col} TEXT`);
}

// ── App ────────────────────────────────────────────────────────────────────
const app = express();
app.set("trust proxy", true);
app.use(express.json({ limit: "5mb" }));

// Best-effort city/country lookup via free ipapi.co (no key). Cached in-memory.
const geoCache = new Map();
async function geo(ip) {
  if (!ip || ip === "::1" || ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("::ffff:127.")) return { city: "local", country: "local" };
  if (geoCache.has(ip)) return geoCache.get(ip);
  try {
    const r = await fetch(`https://ipapi.co/${ip}/json/`, { signal: AbortSignal.timeout(1500) });
    const j = await r.json();
    const out = { city: j.city || null, country: j.country_name || j.country || null, region: j.region || null };
    geoCache.set(ip, out);
    return out;
  } catch { const out = { city: null, country: null }; geoCache.set(ip, out); return out; }
}

app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "dashboard.html")));
app.get("/browse", (_req, res) => res.sendFile(path.join(__dirname, "sessions.html")));
app.get("/health", (_req, res) => res.json({ ok: true, db: DB_PATH, pricing_models: Object.keys(PRICING).length }));

app.use((req, res, next) => {
  if (!TOKEN) return next();
  const h = req.headers.authorization || "";
  if (h === `Bearer ${TOKEN}`) return next();
  if (req.query.token === TOKEN) return next();
  return res.status(401).json({ error: "unauthorized" });
});

const insert = db.prepare(`
  INSERT INTO events (ts, event, session_id, user_email, user_name, team, department,
    host, platform, cwd, model,
    input_tokens, output_tokens, cache_read_tokens, cache_create_tokens, tool_name,
    client_ip, client_city, client_country, user_agent, payload_json)
  VALUES (@ts, @event, @session_id, @user_email, @user_name, @team, @department,
    @host, @platform, @cwd, @model,
    @input_tokens, @output_tokens, @cache_read_tokens, @cache_create_tokens, @tool_name,
    @client_ip, @client_city, @client_country, @user_agent, @payload_json)
`);

app.post("/events", async (req, res) => {
  const b = req.body || {};
  const u = b.usage || {};
  const ip = (req.ip || req.socket.remoteAddress || "").replace(/^::ffff:/, "");
  const ua = req.get("user-agent") || null;
  let city = null, country = null;
  try { const g = await geo(ip); city = g.city; country = g.country; } catch {}
  try {
    insert.run({
      ts: b.ts || new Date().toISOString(),
      event: b.event || "unknown",
      session_id: b.session_id || null,
      user_email: b.user?.email || null,
      user_name:  b.user?.name || null,
      team:       b.user?.team || null,
      department: b.user?.department || null,
      host: b.user?.host || null,
      platform: b.user?.platform || null,
      cwd: b.cwd || null,
      model: b.model || null,
      input_tokens: u.input_tokens || 0,
      output_tokens: u.output_tokens || 0,
      cache_read_tokens: u.cache_read_input_tokens || 0,
      cache_create_tokens: u.cache_creation_input_tokens || 0,
      tool_name: b.hook_payload?.tool_name || null,
      client_ip: ip || null,
      client_city: city,
      client_country: country,
      user_agent: ua,
      payload_json: JSON.stringify(b),
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ── Helpers ────────────────────────────────────────────────────────────────
function whereClause(req) {
  const days = Math.max(1, parseInt(req.query.days || "14", 10));
  const since = new Date(Date.now() - days * 86400_000).toISOString();
  const filters = ["ts >= @since"];
  const params = { since };
  if (req.query.team)  { filters.push("team = @team");   params.team  = req.query.team;  }
  if (req.query.user)  { filters.push("user_email = @user"); params.user = req.query.user; }
  if (req.query.model) { filters.push("model = @model"); params.model = req.query.model; }
  return { where: filters.join(" AND "), params, days, since };
}

// ── Endpoints ──────────────────────────────────────────────────────────────
app.get("/stats", (req, res) => {
  const { where, params, days, since } = whereClause(req);
  const totals = db.prepare(`
    SELECT COUNT(*) AS events,
           COUNT(DISTINCT session_id) AS sessions,
           COUNT(DISTINCT user_email) AS users,
           COUNT(DISTINCT team)       AS teams,
           COALESCE(SUM(input_tokens),0)  AS input_tokens,
           COALESCE(SUM(output_tokens),0) AS output_tokens,
           COALESCE(SUM(cache_read_tokens),0)   AS cache_read_tokens,
           COALESCE(SUM(cache_create_tokens),0) AS cache_create_tokens
    FROM events WHERE ${where}
  `).get(params);
  const byModel = db.prepare(`
    SELECT model, COUNT(*) n,
           SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens
    FROM events WHERE ${where} AND model IS NOT NULL
    GROUP BY model ORDER BY n DESC
  `).all(params);
  for (const m of byModel) m.cost_usd = cost(m);
  const byTool = db.prepare(`
    SELECT tool_name, COUNT(*) n FROM events
    WHERE ${where} AND tool_name IS NOT NULL AND event = 'pre_tool'
    GROUP BY tool_name ORDER BY n DESC LIMIT 20
  `).all(params);
  const byUser = db.prepare(`
    SELECT user_email, team, COUNT(DISTINCT session_id) sessions,
           SUM(input_tokens+output_tokens) tokens
    FROM events WHERE ${where} AND user_email IS NOT NULL
    GROUP BY user_email ORDER BY tokens DESC LIMIT 20
  `).all(params);
  totals.cost_usd = byModel.reduce((s, m) => s + m.cost_usd, 0);
  res.json({ days, since, totals, byModel, byTool, byUser, filters: { team: req.query.team, user: req.query.user, model: req.query.model } });
});

app.get("/timeseries", (req, res) => {
  const { where, params, days } = whereClause(req);
  const rows = db.prepare(`
    SELECT substr(ts,1,10) day, model,
           SUM(input_tokens) input_tokens,
           SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens)   cache_read_tokens,
           SUM(cache_create_tokens) cache_create_tokens,
           COUNT(DISTINCT session_id) sessions,
           COUNT(DISTINCT user_email) users
    FROM events WHERE ${where}
    GROUP BY day, model ORDER BY day ASC
  `).all(params);
  // Roll up by day with cost
  const byDay = {};
  for (const r of rows) {
    const d = byDay[r.day] || (byDay[r.day] = {
      day: r.day, input_tokens:0, output_tokens:0, cache_read_tokens:0, cache_create_tokens:0,
      sessions:0, users:0, cost_usd:0,
    });
    d.input_tokens   += r.input_tokens   || 0;
    d.output_tokens  += r.output_tokens  || 0;
    d.cache_read_tokens   += r.cache_read_tokens   || 0;
    d.cache_create_tokens += r.cache_create_tokens || 0;
    d.cost_usd += cost(r);
  }
  // user/session counts re-query (distincts can't be summed across model splits)
  const dayMeta = db.prepare(`
    SELECT substr(ts,1,10) day,
           COUNT(DISTINCT session_id) sessions,
           COUNT(DISTINCT user_email) users
    FROM events WHERE ${where} GROUP BY day
  `).all(params);
  for (const m of dayMeta) if (byDay[m.day]) { byDay[m.day].sessions = m.sessions; byDay[m.day].users = m.users; }
  res.json({ days, rows: Object.values(byDay).sort((a,b) => a.day.localeCompare(b.day)) });
});

app.get("/users", (req, res) => {
  const { where, params } = whereClause(req);
  const rows = db.prepare(`
    SELECT user_email, COALESCE(MAX(user_name),'') user_name, COALESCE(MAX(team),'') team,
           COUNT(DISTINCT session_id) sessions,
           COUNT(*) events,
           SUM(input_tokens)  input_tokens,
           SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens)   cache_read_tokens,
           SUM(cache_create_tokens) cache_create_tokens,
           MAX(ts) last_seen
    FROM events WHERE ${where} AND user_email IS NOT NULL
    GROUP BY user_email ORDER BY (input_tokens+output_tokens) DESC
  `).all(params);
  // Per-user cost via per-model breakdown
  const perUserModel = db.prepare(`
    SELECT user_email, model,
           SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens
    FROM events WHERE ${where} AND user_email IS NOT NULL
    GROUP BY user_email, model
  `).all(params);
  const costByUser = {};
  for (const r of perUserModel) costByUser[r.user_email] = (costByUser[r.user_email] || 0) + cost(r);
  for (const r of rows) r.cost_usd = costByUser[r.user_email] || 0;
  res.json(rows);
});

app.get("/teams", (req, res) => {
  const { where, params } = whereClause(req);
  const rows = db.prepare(`
    SELECT COALESCE(team,'(unassigned)') team,
           COUNT(DISTINCT user_email) users,
           COUNT(DISTINCT session_id) sessions,
           SUM(input_tokens)  input_tokens,
           SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens,
           SUM(cache_create_tokens) cache_create_tokens
    FROM events WHERE ${where}
    GROUP BY team ORDER BY (input_tokens+output_tokens) DESC
  `).all(params);
  const perTeamModel = db.prepare(`
    SELECT COALESCE(team,'(unassigned)') team, model,
           SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens
    FROM events WHERE ${where}
    GROUP BY team, model
  `).all(params);
  const costByTeam = {};
  for (const r of perTeamModel) costByTeam[r.team] = (costByTeam[r.team] || 0) + cost(r);
  for (const r of rows) r.cost_usd = costByTeam[r.team] || 0;
  res.json(rows);
});

app.get("/cost", (req, res) => {
  const { where, params, days } = whereClause(req);
  const rows = db.prepare(`
    SELECT model,
           SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens
    FROM events WHERE ${where} AND model IS NOT NULL
    GROUP BY model
  `).all(params);
  let total = 0;
  for (const r of rows) { r.cost_usd = cost(r); total += r.cost_usd; }
  res.json({ days, total_usd: total, byModel: rows, pricing: PRICING });
});

app.get("/sessions", (req, res) => {
  const limit = Math.min(500, parseInt(req.query.limit || "100", 10));
  const filters = ["session_id IS NOT NULL"];
  const params = { limit };
  if (req.query.team) { filters.push("team = @team"); params.team = req.query.team; }
  if (req.query.user) { filters.push("user_email = @user"); params.user = req.query.user; }
  const rows = db.prepare(`
    SELECT session_id, user_email, MAX(team) team,
           MIN(ts) started, MAX(ts) last_event,
           COUNT(*) events, MAX(model) model,
           SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens
    FROM events WHERE ${filters.join(" AND ")}
    GROUP BY session_id ORDER BY last_event DESC LIMIT @limit
  `).all(params);
  for (const r of rows) r.cost_usd = cost(r);
  res.json(rows);
});

app.get("/events", (req, res) => {
  const limit = Math.min(1000, parseInt(req.query.limit || "100", 10));
  const session = req.query.session_id;
  const rows = session
    ? db.prepare("SELECT * FROM events WHERE session_id = ? ORDER BY id ASC LIMIT ?").all(session, limit)
    : db.prepare("SELECT * FROM events ORDER BY id DESC LIMIT ?").all(limit);
  res.json(rows);
});

app.get("/export.csv", (req, res) => {
  const { where, params } = whereClause(req);
  const rows = db.prepare(`
    SELECT ts, event, session_id, user_email, team, model, tool_name,
           input_tokens, output_tokens, cache_read_tokens, cache_create_tokens, cwd
    FROM events WHERE ${where} ORDER BY ts ASC
  `).all(params);
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", "attachment; filename=tracker.csv");
  const cols = ["ts","event","session_id","user_email","team","model","tool_name",
    "input_tokens","output_tokens","cache_read_tokens","cache_create_tokens","cost_usd","cwd"];
  res.write(cols.join(",") + "\n");
  for (const r of rows) {
    r.cost_usd = cost(r).toFixed(6);
    res.write(cols.map((c) => {
      const v = r[c] == null ? "" : String(r[c]);
      return v.includes(",") || v.includes('"') ? `"${v.replace(/"/g,'""')}"` : v;
    }).join(",") + "\n");
  }
  res.end();
});

// ── Message ingestion (CCHV-style transcript content) ─────────────────────
const insertMsg = db.prepare(`
  INSERT OR REPLACE INTO messages
    (session_id, seq, ts, role, user_email, team, cwd, model, text, thinking,
     tool_calls_json, tool_result_json,
     input_tokens, output_tokens, cache_read_tokens, cache_create_tokens)
  VALUES (@session_id,@seq,@ts,@role,@user_email,@team,@cwd,@model,@text,@thinking,
     @tool_calls_json,@tool_result_json,
     @input_tokens,@output_tokens,@cache_read_tokens,@cache_create_tokens)
`);

app.post("/messages/bulk", (req, res) => {
  const list = Array.isArray(req.body?.messages) ? req.body.messages : [];
  const tx = db.transaction((rows) => { for (const r of rows) insertMsg.run(r); });
  try {
    tx(list.map((m) => ({
      session_id: m.session_id,
      seq: m.seq,
      ts: m.ts,
      role: m.role || "user",
      user_email: m.user_email || null,
      team: m.team || null,
      cwd: m.cwd || null,
      model: m.model || null,
      text: m.text || null,
      thinking: m.thinking || null,
      tool_calls_json: m.tool_calls ? JSON.stringify(m.tool_calls) : null,
      tool_result_json: m.tool_result ? JSON.stringify(m.tool_result) : null,
      input_tokens: m.input_tokens || 0,
      output_tokens: m.output_tokens || 0,
      cache_read_tokens: m.cache_read_tokens || 0,
      cache_create_tokens: m.cache_create_tokens || 0,
    })));
    res.json({ ok: true, inserted: list.length });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// Sessions for the browse page (filterable by user/team, with summary)
app.get("/api/sessions", (req, res) => {
  const limit = Math.min(1000, parseInt(req.query.limit || "200", 10));
  const filters = ["1=1"];
  const params = { limit };
  if (req.query.user) { filters.push("user_email = @user"); params.user = req.query.user; }
  if (req.query.team) { filters.push("team = @team");       params.team = req.query.team; }
  if (req.query.q)    { filters.push("(session_id LIKE @q OR cwd LIKE @q)"); params.q = `%${req.query.q}%`; }
  const rows = db.prepare(`
    SELECT s.session_id, s.user_email, MAX(s.team) team, MAX(s.cwd) cwd, MAX(s.model) model,
           MIN(s.ts) started, MAX(s.ts) last_event,
           COUNT(*) events,
           SUM(s.input_tokens) input_tokens,
           SUM(s.output_tokens) output_tokens,
           SUM(s.cache_read_tokens) cache_read_tokens,
           SUM(s.cache_create_tokens) cache_create_tokens,
           (SELECT COUNT(*) FROM messages m WHERE m.session_id = s.session_id) message_count,
           (SELECT text FROM messages m
            WHERE m.session_id = s.session_id AND m.role = 'user' AND m.text IS NOT NULL
            ORDER BY m.seq ASC LIMIT 1) first_user_msg
    FROM events s WHERE ${filters.join(" AND ")} AND s.session_id IS NOT NULL
    GROUP BY s.session_id ORDER BY last_event DESC LIMIT @limit
  `).all(params);
  for (const r of rows) r.cost_usd = cost(r);
  res.json(rows);
});

// Distinct users (for the picker)
app.get("/api/users", (req, res) => {
  const rows = db.prepare(`
    SELECT user_email,
           MAX(user_name) user_name,
           MAX(team) team,
           COUNT(DISTINCT session_id) sessions,
           MAX(ts) last_seen
    FROM events WHERE user_email IS NOT NULL
    GROUP BY user_email ORDER BY last_seen DESC
  `).all();
  res.json(rows);
});

// Full message timeline of a session
// User plan inference: looks at last N days of activity for one user and
// suggests the most economical Claude plan based on model mix + monthly cost.
app.get("/api/users/:email/plan", (req, res) => {
  const days = Math.max(1, parseInt(req.query.days || "30", 10));
  const since = new Date(Date.now() - days * 86400_000).toISOString();
  const email = req.params.email;

  const byModel = db.prepare(`
    SELECT model,
           SUM(input_tokens)  input_tokens,
           SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens)   cache_read_tokens,
           SUM(cache_create_tokens) cache_create_tokens,
           COUNT(DISTINCT session_id) sessions,
           COUNT(*) events
    FROM events WHERE user_email = ? AND ts >= ? AND model IS NOT NULL
    GROUP BY model ORDER BY (input_tokens+output_tokens) DESC
  `).all(email, since);

  let totalCost = 0;
  for (const m of byModel) { m.cost_usd = cost(m); totalCost += m.cost_usd; }

  const totals = db.prepare(`
    SELECT COUNT(DISTINCT session_id) sessions,
           COUNT(DISTINCT substr(ts,1,10)) active_days,
           MIN(ts) first_seen, MAX(ts) last_seen,
           SUM(input_tokens) input_tokens,
           SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens
    FROM events WHERE user_email = ? AND ts >= ?
  `).get(email, since);

  const monthlyCost = (totalCost / days) * 30;
  const usesOpus    = byModel.some(m => /opus/i.test(m.model || ""));
  const opusShare   = byModel.filter(m => /opus/i.test(m.model || "")).reduce((s,m)=>s+(m.input_tokens+m.output_tokens),0)
                    / Math.max(1, byModel.reduce((s,m)=>s+(m.input_tokens+m.output_tokens),0));
  const sonnetShare = byModel.filter(m => /sonnet/i.test(m.model || "")).reduce((s,m)=>s+(m.input_tokens+m.output_tokens),0)
                    / Math.max(1, byModel.reduce((s,m)=>s+(m.input_tokens+m.output_tokens),0));
  const cacheHit    = (totals.cache_read_tokens || 0) / Math.max(1, (totals.input_tokens || 0) + (totals.cache_read_tokens || 0));

  // Plan options (rough public pricing, adjustable)
  const plans = [
    { id: "pro",       name: "Claude Pro",        price_usd: 20,  notes: "개인 사용. Sonnet 위주, Opus는 제한. 메시지 한도 5h당." },
    { id: "max-5x",    name: "Claude Max (5×)",   price_usd: 100, notes: "Pro의 5배 한도. Opus 더 자유롭게." },
    { id: "max-20x",   name: "Claude Max (20×)",  price_usd: 200, notes: "Pro의 20배 한도. 헤비 Opus 사용자." },
    { id: "team",      name: "Claude Team",       price_usd: 25,  notes: "1인당. 협업/공유 워크스페이스." },
    { id: "api",       name: "API pay-as-you-go", price_usd: Math.round(monthlyCost), notes: "실비 청구. Claude Code의 기본." },
  ];

  // Recommendation logic
  let recommended;
  if (monthlyCost < 18) {
    recommended = "pro";
  } else if (monthlyCost < 80 && opusShare < 0.3) {
    recommended = "pro";
  } else if (monthlyCost < 180 && opusShare < 0.6) {
    recommended = "max-5x";
  } else if (monthlyCost < 600) {
    recommended = "max-20x";
  } else {
    recommended = "api";
  }
  // If they're already on API and consistently using a lot, Max-20x is often cheaper.
  const cheapestSubscription = monthlyCost > 200 && monthlyCost < 600 ? "max-20x" : recommended;

  // Heavy/light user classification
  const dailyAvgCost = totalCost / Math.max(1, days);
  const tier = dailyAvgCost > 20 ? "헤비"
             : dailyAvgCost > 5  ? "활발"
             : dailyAvgCost > 1  ? "정기"
             : "라이트";

  res.json({
    email, days,
    totals: { ...totals, cost_usd: totalCost, monthly_projected_usd: monthlyCost, cache_hit_rate: cacheHit },
    byModel,
    inference: {
      tier,
      opus_share: opusShare,
      sonnet_share: sonnetShare,
      recommended_plan: cheapestSubscription,
      reason: monthlyCost < 18  ? "월 $18 미만 → Pro로 충분"
            : monthlyCost < 80  ? "Opus 비중 낮음 → Pro 권장"
            : monthlyCost < 180 ? "중간 사용량 + Opus 비중 보통 → Max 5× 권장"
            : monthlyCost < 600 ? "헤비 사용 + Opus 위주 → Max 20× 권장"
            : "월 $600+ → API 종량제가 비용 협상 우위",
    },
    plans,
  });
});

app.get("/api/sessions/:id/messages", (req, res) => {
  const rows = db.prepare(`
    SELECT seq, ts, role, model, text, thinking,
           tool_calls_json, tool_result_json,
           input_tokens, output_tokens, cache_read_tokens, cache_create_tokens
    FROM messages WHERE session_id = ? ORDER BY seq ASC
  `).all(req.params.id);
  for (const r of rows) {
    r.tool_calls  = r.tool_calls_json  ? JSON.parse(r.tool_calls_json)  : null;
    r.tool_result = r.tool_result_json ? JSON.parse(r.tool_result_json) : null;
    delete r.tool_calls_json; delete r.tool_result_json;
  }
  const head = db.prepare(`
    SELECT session_id, MAX(user_email) user_email, MAX(user_name) user_name,
           MAX(team) team, MAX(cwd) cwd, MAX(model) model,
           MAX(host) host, MAX(platform) platform,
           MAX(client_ip) client_ip, MAX(client_city) client_city, MAX(client_country) client_country,
           MAX(user_agent) user_agent,
           MIN(ts) started, MAX(ts) last_event,
           SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens
    FROM events WHERE session_id = ?
  `).get(req.params.id);
  if (head) head.cost_usd = cost(head);
  res.json({ session: head, messages: rows });
});

app.listen(PORT, () => {
  console.log(`claude-tracker listening on :${PORT}  (db=${DB_PATH}, auth=${TOKEN ? "on" : "off"})`);
});
