/**
 * claude-tracker — Cloudflare Worker
 *
 * Bindings (wrangler.toml):
 *   DB     : D1Database
 *   BLOBS  : R2Bucket
 *   ASSETS : Fetcher (static)
 *
 * Routes mirror the legacy Express server. Key changes:
 *   - PII/secret masking on ingestion (NOT email)
 *   - R2 offload for big payloads
 *   - Cloudflare Access SSO auth
 *   - Audit log on read paths
 *   - Cron: retention purge + audit rollup
 */
import { Hono } from "hono";
import { getActor, isAdmin, generateToken, hashToken, type Actor } from "./auth";
import { maskString, maskJsonValue } from "./masking";
import { costUsd } from "./pricing";
import { maybeOffload, loadIfOffloaded } from "./r2helpers";

type Env = {
  DB: D1Database;
  BLOBS: R2Bucket;
  ASSETS: Fetcher;
  TRACKER_TOKEN?: string;
  ADMIN_EMAILS?: string;
  RETENTION_DAYS?: string;
};

const app = new Hono<{ Bindings: Env; Variables: { actor: Actor } }>();

// ── Static dashboard ───────────────────────────────────────────────────────
app.get("/", (c) => c.env.ASSETS.fetch(new Request(new URL("/dashboard.html", c.req.url))));
app.get("/browse", (c) => c.env.ASSETS.fetch(new Request(new URL("/sessions.html", c.req.url))));
app.get("/dashboard.html", (c) => c.env.ASSETS.fetch(c.req.raw));
app.get("/sessions.html", (c) => c.env.ASSETS.fetch(c.req.raw));
app.get("/health", (c) => c.json({ ok: true, environment: (c.env as any).ENVIRONMENT || "unknown" }));

// ── Auth middleware (skip for static) ──────────────────────────────────────
app.use("/api/*", async (c, next) => {
  const actor = await getActor(c);
  if (!actor) return c.json({ error: "unauthorized" }, 401);
  c.set("actor", actor);
  await next();
});
app.use("/events", async (c, next) => {
  // Ingestion endpoint — accept Access OR bearer
  const actor = await getActor(c);
  if (!actor) return c.json({ error: "unauthorized" }, 401);
  c.set("actor", actor);
  await next();
});
app.use("/messages/bulk", async (c, next) => {
  const actor = await getActor(c);
  if (!actor) return c.json({ error: "unauthorized" }, 401);
  c.set("actor", actor);
  await next();
});

// ── Helpers ────────────────────────────────────────────────────────────────
async function audit(env: Env, actor: Actor, action: string, target_user: string | null, target_session: string | null, ip: string | null) {
  if (actor.via === "legacy-bearer") return; // Don't log shared-token machine traffic
  await env.DB.prepare(
    "INSERT INTO access_log (ts, actor_email, action, target_user, target_session, ip) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(new Date().toISOString(), actor.email, action, target_user, target_session, ip).run();
}

function sinceParam(c: any) {
  const days = Math.max(1, parseInt(c.req.query("days") || "14", 10));
  return { days, since: new Date(Date.now() - days * 86400_000).toISOString() };
}

function teamScope(actor: Actor, env: Env): { sql: string; param?: string } {
  // Admins see everything. Others see their own team only.
  if (isAdmin(actor, env)) return { sql: "" };
  return { sql: " AND (user_email = ? OR team IN (SELECT team FROM events WHERE user_email = ? LIMIT 1))", param: actor.email };
}

// ── Ingestion ──────────────────────────────────────────────────────────────
app.post("/events", async (c) => {
  const b = await c.req.json<any>();
  const u = b.usage || {};
  const ip = c.req.header("cf-connecting-ip") || null;
  const ua = c.req.header("user-agent") || null;
  const country = c.req.header("cf-ipcountry") || null;
  const city = (c.req.raw as any).cf?.city || null;

  // Mask payload but never the user's own email (it's our identity key).
  const maskedPayload = maskJsonValue(b);
  const payloadJson = JSON.stringify(maskedPayload);
  const off = await maybeOffload(c.env.BLOBS, `events/${new Date().toISOString().slice(0, 10)}`, payloadJson);

  await c.env.DB.prepare(`
    INSERT INTO events (ts, event, session_id, user_email, user_name, team, department,
      host, platform, cwd, model,
      input_tokens, output_tokens, cache_read_tokens, cache_create_tokens, tool_name,
      client_ip, client_city, client_country, user_agent,
      payload_json, payload_r2_key)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).bind(
    b.ts || new Date().toISOString(),
    b.event || "unknown",
    b.session_id || null,
    b.user?.email || null,
    b.user?.name || null,
    b.user?.team || null,
    b.user?.department || null,
    b.user?.host ? maskString(b.user.host) : null,
    b.user?.platform || null,
    b.cwd ? maskString(b.cwd) : null,
    b.model || null,
    u.input_tokens || 0,
    u.output_tokens || 0,
    u.cache_read_input_tokens || 0,
    u.cache_creation_input_tokens || 0,
    b.hook_payload?.tool_name || null,
    ip, city, country, ua,
    off.inline, off.key
  ).run();

  return c.json({ ok: true });
});

app.post("/messages/bulk", async (c) => {
  const body = await c.req.json<{ messages: any[] }>();
  const list = Array.isArray(body?.messages) ? body.messages : [];
  if (!list.length) return c.json({ ok: true, inserted: 0 });

  // Process in chunks to stay within D1 batch limits (100 statements)
  const stmts = [];
  for (const m of list) {
    const maskedText = maskString(m.text);
    const maskedThinking = maskString(m.thinking);
    const maskedToolCalls = m.tool_calls ? JSON.stringify(maskJsonValue(m.tool_calls)) : null;
    const maskedToolResult = m.tool_result ? JSON.stringify(maskJsonValue(m.tool_result)) : null;

    const textOff = await maybeOffload(c.env.BLOBS, `msg-text/${m.session_id}`, maskedText);
    const resultOff = await maybeOffload(c.env.BLOBS, `msg-result/${m.session_id}`, maskedToolResult);

    stmts.push(c.env.DB.prepare(`
      INSERT OR REPLACE INTO messages
        (session_id, seq, ts, role, user_email, team, cwd, model,
         text, thinking, tool_calls_json, tool_result_json,
         text_r2_key, result_r2_key,
         input_tokens, output_tokens, cache_read_tokens, cache_create_tokens)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).bind(
      m.session_id, m.seq, m.ts, m.role || "user",
      m.user_email || null, m.team || null, maskString(m.cwd) || null, m.model || null,
      textOff.inline, maskedThinking,
      maskedToolCalls, resultOff.inline,
      textOff.key, resultOff.key,
      m.input_tokens || 0, m.output_tokens || 0,
      m.cache_read_tokens || 0, m.cache_create_tokens || 0
    ));
  }

  // D1 batches up to 100 statements per call
  for (let i = 0; i < stmts.length; i += 100) {
    await c.env.DB.batch(stmts.slice(i, i + 100));
  }
  return c.json({ ok: true, inserted: list.length });
});

// ── Read APIs (audited) ────────────────────────────────────────────────────
app.get("/api/users", async (c) => {
  const actor = c.get("actor");
  const scope = teamScope(actor, c.env);
  const sql = `
    SELECT user_email, MAX(user_name) user_name, MAX(team) team,
           COUNT(DISTINCT session_id) sessions, MAX(ts) last_seen
    FROM events WHERE user_email IS NOT NULL ${scope.sql}
    GROUP BY user_email ORDER BY last_seen DESC LIMIT 500`;
  const stmt = scope.param
    ? c.env.DB.prepare(sql).bind(actor.email, actor.email)
    : c.env.DB.prepare(sql);
  const r = await stmt.all();
  await audit(c.env, actor, "list_users", null, null, c.req.header("cf-connecting-ip") || null);
  return c.json(r.results);
});

app.get("/api/sessions", async (c) => {
  const actor = c.get("actor");
  const targetUser = c.req.query("user");
  if (!isAdmin(actor, c.env) && targetUser && targetUser !== actor.email) {
    // Allow team-mates only
    const sameTeam = await c.env.DB.prepare(
      "SELECT 1 FROM events WHERE user_email = ? AND team IN (SELECT team FROM events WHERE user_email = ? LIMIT 1) LIMIT 1"
    ).bind(targetUser, actor.email).first();
    if (!sameTeam) return c.json({ error: "forbidden" }, 403);
  }
  const limit = Math.min(1000, parseInt(c.req.query("limit") || "200", 10));
  const filters = ["session_id IS NOT NULL"]; const params: any[] = [];
  if (targetUser) { filters.push("user_email = ?"); params.push(targetUser); }
  const team = c.req.query("team");
  if (team) { filters.push("team = ?"); params.push(team); }
  params.push(limit);
  const r = await c.env.DB.prepare(`
    SELECT session_id, MAX(user_email) user_email, MAX(team) team,
           MAX(cwd) cwd, MAX(model) model,
           MIN(ts) started, MAX(ts) last_event,
           COUNT(*) events,
           SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens,
           (SELECT text FROM messages WHERE session_id = events.session_id AND role = 'user' AND text IS NOT NULL ORDER BY seq ASC LIMIT 1) first_user_msg
    FROM events WHERE ${filters.join(" AND ")}
    GROUP BY session_id ORDER BY last_event DESC LIMIT ?
  `).bind(...params).all<any>();
  const rows = (r.results || []).map((row: any) => ({ ...row, cost_usd: costUsd(row) }));
  await audit(c.env, actor, "list_sessions", targetUser || null, null, c.req.header("cf-connecting-ip") || null);
  return c.json(rows);
});

app.get("/api/sessions/:id/messages", async (c) => {
  const actor = c.get("actor");
  const sid = c.req.param("id");
  const head = await c.env.DB.prepare(`
    SELECT session_id, MAX(user_email) user_email, MAX(user_name) user_name,
           MAX(team) team, MAX(cwd) cwd, MAX(model) model,
           MAX(host) host, MAX(platform) platform,
           MAX(client_ip) client_ip, MAX(client_city) client_city, MAX(client_country) client_country,
           MIN(ts) started, MAX(ts) last_event,
           SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens
    FROM events WHERE session_id = ?
  `).bind(sid).first<any>();

  if (head && !isAdmin(actor, c.env) && head.user_email !== actor.email) {
    const sameTeam = head.team && (await c.env.DB.prepare(
      "SELECT 1 FROM events WHERE user_email = ? AND team = ? LIMIT 1"
    ).bind(actor.email, head.team).first());
    if (!sameTeam) return c.json({ error: "forbidden" }, 403);
  }
  if (head) head.cost_usd = costUsd(head);

  const r = await c.env.DB.prepare(`
    SELECT seq, ts, role, model, text, thinking, tool_calls_json, tool_result_json,
           text_r2_key, result_r2_key,
           input_tokens, output_tokens, cache_read_tokens, cache_create_tokens
    FROM messages WHERE session_id = ? ORDER BY seq ASC
  `).bind(sid).all<any>();
  const messages = await Promise.all((r.results || []).map(async (m: any) => {
    if (m.text_r2_key) m.text = await loadIfOffloaded(c.env.BLOBS, m.text_r2_key);
    if (m.result_r2_key) {
      const full = await loadIfOffloaded(c.env.BLOBS, m.result_r2_key);
      if (full) m.tool_result_json = full;
    }
    m.tool_calls = m.tool_calls_json ? JSON.parse(m.tool_calls_json) : null;
    m.tool_result = m.tool_result_json ? JSON.parse(m.tool_result_json) : null;
    delete m.tool_calls_json; delete m.tool_result_json; delete m.text_r2_key; delete m.result_r2_key;
    return m;
  }));

  await audit(c.env, actor, "view_session", head?.user_email || null, sid, c.req.header("cf-connecting-ip") || null);
  return c.json({ session: head, messages });
});

// User plan inference
app.get("/api/users/:email/plan", async (c) => {
  const actor = c.get("actor");
  const email = c.req.param("email");
  if (!isAdmin(actor, c.env) && email !== actor.email) return c.json({ error: "forbidden" }, 403);
  const { days, since } = sinceParam(c);
  const byModel = await c.env.DB.prepare(`
    SELECT model, SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens,
           COUNT(DISTINCT session_id) sessions, COUNT(*) events
    FROM events WHERE user_email = ? AND ts >= ? AND model IS NOT NULL
    GROUP BY model ORDER BY (input_tokens+output_tokens) DESC
  `).bind(email, since).all<any>();
  const totals: any = await c.env.DB.prepare(`
    SELECT COUNT(DISTINCT session_id) sessions, COUNT(DISTINCT substr(ts,1,10)) active_days,
           MIN(ts) first_seen, MAX(ts) last_seen,
           SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens
    FROM events WHERE user_email = ? AND ts >= ?
  `).bind(email, since).first();

  const byModelArr = (byModel.results || []).map((m: any) => ({ ...m, cost_usd: costUsd(m) }));
  const totalCost = byModelArr.reduce((s: number, m: any) => s + m.cost_usd, 0);
  const monthlyCost = (totalCost / days) * 30;
  const opusShare = byModelArr.filter((m: any) => /opus/i.test(m.model || ""))
    .reduce((s: number, m: any) => s + (m.input_tokens + m.output_tokens), 0)
    / Math.max(1, byModelArr.reduce((s: number, m: any) => s + (m.input_tokens + m.output_tokens), 0));
  const cacheHit = (totals.cache_read_tokens || 0) / Math.max(1, (totals.input_tokens || 0) + (totals.cache_read_tokens || 0));

  const plans = [
    { id: "pro",      name: "Claude Pro",        price_usd: 20,  notes: "개인. Sonnet 위주, Opus 제한." },
    { id: "max-5x",   name: "Claude Max (5×)",   price_usd: 100, notes: "Pro의 5배 한도." },
    { id: "max-20x",  name: "Claude Max (20×)",  price_usd: 200, notes: "Pro의 20배. 헤비 Opus." },
    { id: "team",     name: "Claude Team",       price_usd: 25,  notes: "1인당. 협업 워크스페이스." },
    { id: "api",      name: "API pay-as-you-go", price_usd: Math.round(monthlyCost), notes: "실비. Claude Code 기본." },
  ];
  const recommended =
    monthlyCost < 18 ? "pro"
    : monthlyCost < 80 && opusShare < 0.3 ? "pro"
    : monthlyCost < 180 && opusShare < 0.6 ? "max-5x"
    : monthlyCost < 600 ? "max-20x"
    : "api";
  const dailyAvg = totalCost / Math.max(1, days);
  const tier = dailyAvg > 20 ? "헤비" : dailyAvg > 5 ? "활발" : dailyAvg > 1 ? "정기" : "라이트";

  return c.json({
    email, days,
    totals: { ...totals, cost_usd: totalCost, monthly_projected_usd: monthlyCost, cache_hit_rate: cacheHit },
    byModel: byModelArr,
    inference: {
      tier, opus_share: opusShare,
      sonnet_share: byModelArr.filter((m: any) => /sonnet/i.test(m.model || "")).reduce((s: number, m: any) => s + (m.input_tokens + m.output_tokens), 0) / Math.max(1, byModelArr.reduce((s: number, m: any) => s + (m.input_tokens + m.output_tokens), 0)),
      recommended_plan: recommended,
      reason:
        monthlyCost < 18  ? "월 $18 미만 → Pro로 충분"
        : monthlyCost < 80  ? "Opus 비중 낮음 → Pro 권장"
        : monthlyCost < 180 ? "중간 사용량 + Opus 비중 보통 → Max 5× 권장"
        : monthlyCost < 600 ? "헤비 사용 + Opus 위주 → Max 20× 권장"
        : "월 $600+ → API 종량제가 유리",
    },
    plans,
  });
});

// ── Legacy dashboard endpoints (parity with Express server) ────────────────
// These are what `dashboard.html` calls today. They map to D1 directly.

function whereTeamUserModel(c: any): { where: string; bind: any[]; days: number; since: string } {
  const days = Math.max(1, parseInt(c.req.query("days") || "14", 10));
  const since = new Date(Date.now() - days * 86400_000).toISOString();
  const filters = ["ts >= ?"]; const bind: any[] = [since];
  if (c.req.query("team"))  { filters.push("team = ?");       bind.push(c.req.query("team")); }
  if (c.req.query("user"))  { filters.push("user_email = ?"); bind.push(c.req.query("user")); }
  if (c.req.query("model")) { filters.push("model = ?");      bind.push(c.req.query("model")); }
  return { where: filters.join(" AND "), bind, days, since };
}

app.use("/stats", async (c, next) => { const a = await getActor(c); if (!a) return c.json({error:"unauthorized"},401); c.set("actor", a); await next(); });
app.use("/timeseries", async (c, next) => { const a = await getActor(c); if (!a) return c.json({error:"unauthorized"},401); c.set("actor", a); await next(); });
app.use("/teams", async (c, next) => { const a = await getActor(c); if (!a) return c.json({error:"unauthorized"},401); c.set("actor", a); await next(); });
app.use("/users", async (c, next) => { const a = await getActor(c); if (!a) return c.json({error:"unauthorized"},401); c.set("actor", a); await next(); });
app.use("/sessions", async (c, next) => { const a = await getActor(c); if (!a) return c.json({error:"unauthorized"},401); c.set("actor", a); await next(); });
app.use("/cost", async (c, next) => { const a = await getActor(c); if (!a) return c.json({error:"unauthorized"},401); c.set("actor", a); await next(); });
app.use("/export.csv", async (c, next) => { const a = await getActor(c); if (!a) return c.json({error:"unauthorized"},401); c.set("actor", a); await next(); });

app.get("/stats", async (c) => {
  const { where, bind, days, since } = whereTeamUserModel(c);
  const totals: any = await c.env.DB.prepare(`
    SELECT COUNT(*) AS events, COUNT(DISTINCT session_id) AS sessions,
           COUNT(DISTINCT user_email) AS users, COUNT(DISTINCT team) AS teams,
           COALESCE(SUM(input_tokens),0) AS input_tokens,
           COALESCE(SUM(output_tokens),0) AS output_tokens,
           COALESCE(SUM(cache_read_tokens),0) AS cache_read_tokens,
           COALESCE(SUM(cache_create_tokens),0) AS cache_create_tokens
    FROM events WHERE ${where}`).bind(...bind).first();
  const byModelRes = await c.env.DB.prepare(`
    SELECT model, COUNT(*) n,
           SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens
    FROM events WHERE ${where} AND model IS NOT NULL GROUP BY model ORDER BY n DESC`).bind(...bind).all<any>();
  const byModel = (byModelRes.results || []).map((m: any) => ({ ...m, cost_usd: costUsd(m) }));
  const byToolRes = await c.env.DB.prepare(`
    SELECT tool_name, COUNT(*) n FROM events
    WHERE ${where} AND tool_name IS NOT NULL AND event = 'pre_tool'
    GROUP BY tool_name ORDER BY n DESC LIMIT 20`).bind(...bind).all<any>();
  const byUserRes = await c.env.DB.prepare(`
    SELECT user_email, MAX(team) team, COUNT(DISTINCT session_id) sessions,
           SUM(input_tokens+output_tokens) tokens
    FROM events WHERE ${where} AND user_email IS NOT NULL
    GROUP BY user_email ORDER BY tokens DESC LIMIT 20`).bind(...bind).all<any>();
  totals.cost_usd = byModel.reduce((s, m) => s + m.cost_usd, 0);
  return c.json({ days, since, totals, byModel, byTool: byToolRes.results || [], byUser: byUserRes.results || [], filters: { team: c.req.query("team"), user: c.req.query("user"), model: c.req.query("model") } });
});

app.get("/timeseries", async (c) => {
  const { where, bind, days } = whereTeamUserModel(c);
  const rows = await c.env.DB.prepare(`
    SELECT substr(ts,1,10) day, model,
           SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens
    FROM events WHERE ${where} GROUP BY day, model ORDER BY day ASC`).bind(...bind).all<any>();
  const byDay: Record<string, any> = {};
  for (const r of rows.results || []) {
    const d = byDay[r.day] || (byDay[r.day] = { day: r.day, input_tokens:0, output_tokens:0, cache_read_tokens:0, cache_create_tokens:0, sessions:0, users:0, cost_usd:0 });
    d.input_tokens += r.input_tokens || 0; d.output_tokens += r.output_tokens || 0;
    d.cache_read_tokens += r.cache_read_tokens || 0; d.cache_create_tokens += r.cache_create_tokens || 0;
    d.cost_usd += costUsd(r);
  }
  const meta = await c.env.DB.prepare(`
    SELECT substr(ts,1,10) day, COUNT(DISTINCT session_id) sessions, COUNT(DISTINCT user_email) users
    FROM events WHERE ${where} GROUP BY day`).bind(...bind).all<any>();
  for (const m of meta.results || []) if (byDay[m.day]) { byDay[m.day].sessions = m.sessions; byDay[m.day].users = m.users; }
  return c.json({ days, rows: Object.values(byDay).sort((a:any,b:any) => a.day.localeCompare(b.day)) });
});

app.get("/teams", async (c) => {
  const { where, bind } = whereTeamUserModel(c);
  const rowsRes = await c.env.DB.prepare(`
    SELECT COALESCE(team,'(unassigned)') team, COUNT(DISTINCT user_email) users,
           COUNT(DISTINCT session_id) sessions,
           SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens
    FROM events WHERE ${where} GROUP BY team ORDER BY (input_tokens+output_tokens) DESC`).bind(...bind).all<any>();
  const perTeamModelRes = await c.env.DB.prepare(`
    SELECT COALESCE(team,'(unassigned)') team, model,
           SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens
    FROM events WHERE ${where} GROUP BY team, model`).bind(...bind).all<any>();
  const cby: Record<string, number> = {};
  for (const r of perTeamModelRes.results || []) cby[r.team] = (cby[r.team] || 0) + costUsd(r);
  const rows = (rowsRes.results || []).map((r: any) => ({ ...r, cost_usd: cby[r.team] || 0 }));
  return c.json(rows);
});

app.get("/users", async (c) => {
  const { where, bind } = whereTeamUserModel(c);
  const rowsRes = await c.env.DB.prepare(`
    SELECT user_email, COALESCE(MAX(user_name),'') user_name, COALESCE(MAX(team),'') team,
           COUNT(DISTINCT session_id) sessions, COUNT(*) events,
           SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens,
           MAX(ts) last_seen
    FROM events WHERE ${where} AND user_email IS NOT NULL
    GROUP BY user_email ORDER BY (input_tokens+output_tokens) DESC`).bind(...bind).all<any>();
  const perUMRes = await c.env.DB.prepare(`
    SELECT user_email, model, SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens
    FROM events WHERE ${where} AND user_email IS NOT NULL GROUP BY user_email, model`).bind(...bind).all<any>();
  const cby: Record<string, number> = {};
  for (const r of perUMRes.results || []) cby[r.user_email] = (cby[r.user_email] || 0) + costUsd(r);
  const rows = (rowsRes.results || []).map((r: any) => ({ ...r, cost_usd: cby[r.user_email] || 0 }));
  return c.json(rows);
});

app.get("/sessions", async (c) => {
  const limit = Math.min(500, parseInt(c.req.query("limit") || "100", 10));
  const filters = ["session_id IS NOT NULL"]; const bind: any[] = [];
  if (c.req.query("team")) { filters.push("team = ?"); bind.push(c.req.query("team")); }
  if (c.req.query("user")) { filters.push("user_email = ?"); bind.push(c.req.query("user")); }
  bind.push(limit);
  const r = await c.env.DB.prepare(`
    SELECT session_id, MAX(user_email) user_email, MAX(team) team,
           MIN(ts) started, MAX(ts) last_event,
           COUNT(*) events, MAX(model) model,
           SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens
    FROM events WHERE ${filters.join(" AND ")}
    GROUP BY session_id ORDER BY last_event DESC LIMIT ?`).bind(...bind).all<any>();
  const rows = (r.results || []).map((row: any) => ({ ...row, cost_usd: costUsd(row) }));
  return c.json(rows);
});

app.get("/cost", async (c) => {
  const { where, bind, days } = whereTeamUserModel(c);
  const r = await c.env.DB.prepare(`
    SELECT model, SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
           SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens
    FROM events WHERE ${where} AND model IS NOT NULL GROUP BY model`).bind(...bind).all<any>();
  let total = 0;
  const rows = (r.results || []).map((row: any) => { const c2 = costUsd(row); total += c2; return { ...row, cost_usd: c2 }; });
  return c.json({ days, total_usd: total, byModel: rows });
});

app.get("/export.csv", async (c) => {
  const { where, bind } = whereTeamUserModel(c);
  const r = await c.env.DB.prepare(`
    SELECT ts, event, session_id, user_email, team, model, tool_name,
           input_tokens, output_tokens, cache_read_tokens, cache_create_tokens, cwd
    FROM events WHERE ${where} ORDER BY ts ASC LIMIT 50000`).bind(...bind).all<any>();
  const cols = ["ts","event","session_id","user_email","team","model","tool_name","input_tokens","output_tokens","cache_read_tokens","cache_create_tokens","cost_usd","cwd"];
  let csv = cols.join(",") + "\n";
  for (const row of r.results || []) {
    (row as any).cost_usd = costUsd(row).toFixed(6);
    csv += cols.map((k) => {
      const v = (row as any)[k] == null ? "" : String((row as any)[k]);
      return v.includes(",") || v.includes('"') ? `"${v.replace(/"/g,'""')}"` : v;
    }).join(",") + "\n";
  }
  return new Response(csv, { headers: { "Content-Type": "text/csv", "Content-Disposition": "attachment; filename=tracker.csv" } });
});

// Audit log (admin only)
app.get("/api/audit", async (c) => {
  const actor = c.get("actor");
  if (!isAdmin(actor, c.env)) return c.json({ error: "forbidden" }, 403);
  const limit = Math.min(500, parseInt(c.req.query("limit") || "100", 10));
  const r = await c.env.DB.prepare(
    "SELECT * FROM access_log ORDER BY id DESC LIMIT ?"
  ).bind(limit).all();
  return c.json(r.results);
});

// ── Retention purge (cron OR admin-triggered HTTP) ─────────────────────────
async function runRetention(env: Env): Promise<{ events: number; messages: number; r2: number; cutoff: string }> {
  const days = parseInt(env.RETENTION_DAYS || "365", 10);
  const cutoff = new Date(Date.now() - days * 86400_000).toISOString();
  const eventBlobs = await env.DB.prepare(
    "SELECT payload_r2_key k FROM events WHERE ts < ? AND payload_r2_key IS NOT NULL LIMIT 1000"
  ).bind(cutoff).all<{ k: string }>();
  const msgTextBlobs = await env.DB.prepare(
    "SELECT text_r2_key k FROM messages WHERE ts < ? AND text_r2_key IS NOT NULL LIMIT 1000"
  ).bind(cutoff).all<{ k: string }>();
  const msgResultBlobs = await env.DB.prepare(
    "SELECT result_r2_key k FROM messages WHERE ts < ? AND result_r2_key IS NOT NULL LIMIT 1000"
  ).bind(cutoff).all<{ k: string }>();
  const allKeys = [
    ...(eventBlobs.results || []).map((r) => r.k),
    ...(msgTextBlobs.results || []).map((r) => r.k),
    ...(msgResultBlobs.results || []).map((r) => r.k),
  ].filter(Boolean);
  let r2purged = 0;
  for (const key of allKeys) { try { await env.BLOBS.delete(key); r2purged++; } catch {} }
  const e = await env.DB.prepare("DELETE FROM events WHERE ts < ?").bind(cutoff).run();
  const m = await env.DB.prepare("DELETE FROM messages WHERE ts < ?").bind(cutoff).run();
  await env.DB.prepare(
    "INSERT INTO retention_runs (ts, events_purged, messages_purged, r2_objects_purged, notes) VALUES (?,?,?,?,?)"
  ).bind(new Date().toISOString(), e.meta?.changes || 0, m.meta?.changes || 0, r2purged, `cutoff=${cutoff} days=${days}`).run();
  return { events: e.meta?.changes || 0, messages: m.meta?.changes || 0, r2: r2purged, cutoff };
}

// ── Token management (admin only) ─────────────────────────────────────────
app.get("/api/admin/tokens", async (c) => {
  const actor = c.get("actor");
  if (!isAdmin(actor, c.env)) return c.json({ error: "forbidden" }, 403);
  const r = await c.env.DB.prepare(`
    SELECT substr(token_hash,1,8) || '…' AS hash_prefix,
           user_email, user_name, team, is_admin,
           created_at, last_used_at, revoked_at, notes
    FROM tokens ORDER BY created_at DESC LIMIT 200
  `).all();
  return c.json(r.results || []);
});

app.post("/api/admin/tokens", async (c) => {
  const actor = c.get("actor");
  if (!isAdmin(actor, c.env)) return c.json({ error: "forbidden" }, 403);
  const body = await c.req.json<any>();
  if (!body.email) return c.json({ error: "email required" }, 400);
  const raw = generateToken();
  const hash = await hashToken(raw);
  await c.env.DB.prepare(`
    INSERT INTO tokens (token_hash, user_email, user_name, team, is_admin, created_at, notes)
    VALUES (?,?,?,?,?,?,?)
  `).bind(
    hash,
    body.email,
    body.name || null,
    body.team || null,
    body.admin ? 1 : 0,
    new Date().toISOString(),
    body.notes || null
  ).run();
  await audit(c.env, actor, "token_create", body.email, null, c.req.header("cf-connecting-ip") || null);
  return c.json({
    ok: true,
    token: raw,                   // shown ONLY here — store it now
    hash_prefix: hash.slice(0, 8) + "…",
    user_email: body.email,
    instructions: "이 토큰은 한 번만 표시됩니다. /tracker-config 또는 ~/.claude/tracker.json에 저장하세요.",
  });
});

app.delete("/api/admin/tokens/:hashPrefix", async (c) => {
  const actor = c.get("actor");
  if (!isAdmin(actor, c.env)) return c.json({ error: "forbidden" }, 403);
  const prefix = c.req.param("hashPrefix").replace(/…$/, "");
  const r = await c.env.DB.prepare(
    "UPDATE tokens SET revoked_at = ? WHERE token_hash LIKE ? AND revoked_at IS NULL"
  ).bind(new Date().toISOString(), prefix + "%").run();
  await audit(c.env, actor, "token_revoke", null, null, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true, revoked: r.meta?.changes || 0 });
});

// "Whoami" — useful debugging for client setup
app.get("/api/me", async (c) => {
  const a = c.get("actor");
  return c.json({ email: a.email, name: a.name, team: a.team, via: a.via, is_admin: a.is_admin });
});

// Admin endpoint (admin OR shared bearer)
app.post("/api/admin/retention", async (c) => {
  const actor = c.get("actor");
  if (!isAdmin(actor, c.env)) return c.json({ error: "forbidden" }, 403);
  const result = await runRetention(c.env);
  return c.json({ ok: true, ...result });
});

export default {
  fetch: app.fetch,
  async scheduled(_evt: ScheduledEvent, env: Env, _ctx: ExecutionContext) {
    const days = parseInt(env.RETENTION_DAYS || "365", 10);
    const cutoff = new Date(Date.now() - days * 86400_000).toISOString();

    // 1) Find R2 keys we'll lose
    const eventBlobs = await env.DB.prepare(
      "SELECT payload_r2_key k FROM events WHERE ts < ? AND payload_r2_key IS NOT NULL LIMIT 1000"
    ).bind(cutoff).all<{ k: string }>();
    const msgTextBlobs = await env.DB.prepare(
      "SELECT text_r2_key k FROM messages WHERE ts < ? AND text_r2_key IS NOT NULL LIMIT 1000"
    ).bind(cutoff).all<{ k: string }>();
    const msgResultBlobs = await env.DB.prepare(
      "SELECT result_r2_key k FROM messages WHERE ts < ? AND result_r2_key IS NOT NULL LIMIT 1000"
    ).bind(cutoff).all<{ k: string }>();

    const allKeys = [
      ...(eventBlobs.results || []).map((r) => r.k),
      ...(msgTextBlobs.results || []).map((r) => r.k),
      ...(msgResultBlobs.results || []).map((r) => r.k),
    ].filter(Boolean);

    let r2purged = 0;
    for (const key of allKeys) {
      try { await env.BLOBS.delete(key); r2purged++; } catch {}
    }

    const e = await env.DB.prepare("DELETE FROM events WHERE ts < ?").bind(cutoff).run();
    const m = await env.DB.prepare("DELETE FROM messages WHERE ts < ?").bind(cutoff).run();

    await env.DB.prepare(
      "INSERT INTO retention_runs (ts, events_purged, messages_purged, r2_objects_purged, notes) VALUES (?,?,?,?,?)"
    ).bind(
      new Date().toISOString(),
      e.meta?.changes || 0,
      m.meta?.changes || 0,
      r2purged,
      `cutoff=${cutoff} days=${days}`
    ).run();
  },
};
