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
import { getActor, isAdmin, isManagerOrAbove, canSeeUser, canIssueRole, scopeFor, generateToken, hashToken, type Actor } from "./auth";
import { encryptToken, decryptToken } from "./crypto";
import { pingJira, fetchTicket, fetchAssignedOpen } from "./jira";
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
  INTEGRATION_KEY?: string;        // 32-byte hex, AES-GCM
  ANTHROPIC_API_KEY?: string;      // (legacy) Claude 분석용
  GEMINI_API_KEY?: string;         // for /api/sessions/:id/analyze
  GEMINI_MODEL?: string;           // default in wrangler.toml
  AI_GATEWAY_BASE?: string;        // CF AI Gateway URL (region 우회)
};

const app = new Hono<{ Bindings: Env; Variables: { actor: Actor } }>();

// ── Static dashboard ───────────────────────────────────────────────────────
app.get("/", (c) => c.env.ASSETS.fetch(new Request(new URL("/dashboard.html", c.req.url))));
app.get("/browse", (c) => c.env.ASSETS.fetch(new Request(new URL("/sessions.html", c.req.url))));
app.get("/u/:email", (c) => c.env.ASSETS.fetch(new Request(new URL("/profile.html", c.req.url))));
app.get("/p/:slug{.+}", (c) => c.env.ASSETS.fetch(new Request(new URL("/project.html", c.req.url))));
app.get("/project.html", (c) => c.env.ASSETS.fetch(c.req.raw));
app.get("/dashboard.html", (c) => c.env.ASSETS.fetch(c.req.raw));
app.get("/sessions.html", (c) => c.env.ASSETS.fetch(c.req.raw));
app.get("/profile.html", (c) => c.env.ASSETS.fetch(c.req.raw));
app.get("/health", (c) => c.json({ ok: true, environment: (c.env as any).ENVIRONMENT || "unknown" }));

// ── Auth middleware (skip for static) ──────────────────────────────────────
const PUBLIC_API = new Set(["/api/signup"]);
app.use("/api/*", async (c, next) => {
  if (PUBLIC_API.has(new URL(c.req.url).pathname)) return next();
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

// Legacy helper retained for callers that still use teamScope (replaced incrementally).
function teamScope(actor: Actor, _env: Env): { sql: string; params: any[] } {
  return scopeFor(actor);
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

  // Claude Code의 /rename — hook이 transcript에서 customTitle 추출해 보내면 자동 동기화
  if (b.custom_title && b.session_id) {
    try {
      await c.env.DB.prepare(
        `INSERT INTO sessions_meta (session_id, name, updated_by, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(session_id) DO UPDATE SET name=excluded.name, updated_at=excluded.updated_at`
      ).bind(
        b.session_id,
        String(b.custom_title).slice(0, 200),
        b.user?.email ? `${b.user.email} via /rename` : "claude-code:/rename",
        b.ts || new Date().toISOString()
      ).run();
    } catch {}
  }

  return c.json({ ok: true });
});

// hook이 Stop/SessionEnd에서 git 컨텍스트 push
app.post("/api/session-git", async (c) => {
  const actor = c.get("actor");
  const b = await c.req.json<any>().catch(() => ({}));
  if (!b.session_id) return c.json({ error: "session_id required" }, 400);
  // 본인 세션만
  const head: any = await c.env.DB.prepare(
    "SELECT MAX(user_email) user_email FROM events WHERE session_id = ?"
  ).bind(b.session_id).first();
  if (head?.user_email && head.user_email !== actor.email && !isAdmin(actor)) {
    return c.json({ error: "forbidden" }, 403);
  }
  await c.env.DB.prepare(`
    INSERT INTO session_git (session_id, repo_root, remote_url, branch, commits_json, diff_stat, collected_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(session_id) DO UPDATE SET
      repo_root=excluded.repo_root, remote_url=excluded.remote_url,
      branch=excluded.branch, commits_json=excluded.commits_json,
      diff_stat=excluded.diff_stat, collected_at=excluded.collected_at
  `).bind(
    b.session_id,
    b.repo_root || null,
    b.remote_url || null,
    b.branch || null,
    JSON.stringify(b.commits || []),
    b.diff_stat || null,
    new Date().toISOString()
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
  const scope = scopeFor(actor);
  const sql = `
    SELECT user_email, MAX(user_name) user_name, MAX(team) team,
           COUNT(DISTINCT session_id) sessions, MAX(ts) last_seen
    FROM events WHERE user_email IS NOT NULL ${scope.sql}
    GROUP BY user_email ORDER BY last_seen DESC LIMIT 500`;
  const r = await c.env.DB.prepare(sql).bind(...scope.params).all();
  await audit(c.env, actor, "list_users", null, null, c.req.header("cf-connecting-ip") || null);
  return c.json(r.results);
});

app.get("/api/sessions", async (c) => {
  const actor = c.get("actor");
  const targetUser = c.req.query("user");
  if (targetUser && targetUser !== actor.email && !isAdmin(actor)) {
    // For manager/general, must be in same team as target
    if (actor.role === "general") return c.json({ error: "forbidden" }, 403);
    const targetTeam: any = await c.env.DB.prepare(
      "SELECT team FROM events WHERE user_email = ? AND team IS NOT NULL LIMIT 1"
    ).bind(targetUser).first();
    if (!targetTeam || targetTeam.team !== actor.team) return c.json({ error: "forbidden" }, 403);
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
           (SELECT text FROM messages WHERE session_id = events.session_id AND role = 'user' AND text IS NOT NULL ORDER BY seq ASC LIMIT 1) first_user_msg,
           (SELECT name FROM sessions_meta WHERE session_id = events.session_id) custom_name
    FROM events WHERE ${filters.join(" AND ")}
    GROUP BY session_id ORDER BY last_event DESC LIMIT ?
  `).bind(...params).all<any>();
  const rows = (r.results || []).map((row: any) => ({ ...row, cost_usd: costUsd(row) }));
  await audit(c.env, actor, "list_sessions", targetUser || null, null, c.req.header("cf-connecting-ip") || null);
  return c.json(rows);
});

// 세션 이름 변경
app.put("/api/sessions/:id/name", async (c) => {
  const actor = c.get("actor");
  const sid = c.req.param("id");
  const body = await c.req.json<any>().catch(() => ({}));
  const name = (body.name || "").toString().trim().slice(0, 200);
  const head: any = await c.env.DB.prepare(
    "SELECT MAX(user_email) user_email, MAX(team) team FROM events WHERE session_id = ?"
  ).bind(sid).first();
  if (!head?.user_email) return c.json({ error: "session not found" }, 404);
  if (!canSeeUser(actor, head.user_email, head.team)) return c.json({ error: "forbidden" }, 403);
  if (name) {
    await c.env.DB.prepare(
      `INSERT INTO sessions_meta (session_id, name, updated_by, updated_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(session_id) DO UPDATE SET name=excluded.name, updated_by=excluded.updated_by, updated_at=excluded.updated_at`
    ).bind(sid, name, actor.email, new Date().toISOString()).run();
  } else {
    await c.env.DB.prepare("DELETE FROM sessions_meta WHERE session_id = ?").bind(sid).run();
  }
  await audit(c.env, actor, "rename_session", head.user_email, sid, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true, session_id: sid, name });
});

app.get("/api/sessions/:id/messages", async (c) => {
  const actor = c.get("actor");
  const sid = c.req.param("id");
  const head = await c.env.DB.prepare(`
    SELECT e.session_id, MAX(e.user_email) user_email, MAX(e.user_name) user_name,
           MAX(e.team) team, MAX(e.cwd) cwd, MAX(e.model) model,
           MAX(e.host) host, MAX(e.platform) platform,
           MAX(e.client_ip) client_ip, MAX(e.client_city) client_city, MAX(e.client_country) client_country,
           MIN(e.ts) started, MAX(e.ts) last_event,
           SUM(e.input_tokens) input_tokens, SUM(e.output_tokens) output_tokens,
           SUM(e.cache_read_tokens) cache_read_tokens, SUM(e.cache_create_tokens) cache_create_tokens,
           (SELECT name FROM sessions_meta WHERE session_id = e.session_id) custom_name
    FROM events e WHERE e.session_id = ?
  `).bind(sid).first<any>();

  if (head && !canSeeUser(actor, head.user_email, head.team)) {
    return c.json({ error: "forbidden" }, 403);
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
  // Find target user's team to check manager scope
  const target: any = email === actor.email ? { team: actor.team } : await c.env.DB.prepare(
    "SELECT team FROM events WHERE user_email = ? AND team IS NOT NULL LIMIT 1"
  ).bind(email).first();
  if (!canSeeUser(actor, email, target?.team)) return c.json({ error: "forbidden" }, 403);
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
  // Apply actor's role-based scope (admin no-op, manager team-scoped, general self-only)
  const actor = c.get("actor");
  if (actor) {
    const sc = scopeFor(actor);
    if (sc.sql) {
      // sc.sql is " AND <expr> " — strip leading AND for join
      filters.push(sc.sql.trim().replace(/^AND\s+/, ""));
      bind.push(...sc.params);
    }
  }
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
  if (!isAdmin(actor)) return c.json({ error: "forbidden" }, 403);
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
  if (!isManagerOrAbove(actor)) return c.json({ error: "forbidden" }, 403);
  const filters = ["1=1"]; const params: any[] = [];
  if (actor.role === "manager") { filters.push("team = ?"); params.push(actor.team || ""); }
  const r = await c.env.DB.prepare(`
    SELECT substr(token_hash,1,8) || '…' AS hash_prefix,
           user_email, user_name, team, role, is_admin,
           created_at, last_used_at, revoked_at, notes
    FROM tokens WHERE ${filters.join(" AND ")} ORDER BY created_at DESC LIMIT 200
  `).bind(...params).all();
  return c.json(r.results || []);
});

app.post("/api/admin/tokens", async (c) => {
  const actor = c.get("actor");
  if (!isManagerOrAbove(actor)) return c.json({ error: "forbidden" }, 403);
  const body = await c.req.json<any>();
  if (!body.email) return c.json({ error: "email required" }, 400);
  const role = (body.role || (body.admin ? "admin" : "general")) as "admin" | "manager" | "general";
  if (!["admin", "manager", "general"].includes(role)) return c.json({ error: "invalid role" }, 400);
  if (!canIssueRole(actor, role)) return c.json({ error: `cannot issue role=${role}` }, 403);
  if (actor.role === "manager" && body.team && body.team !== actor.team) {
    return c.json({ error: "manager can only invite into own team" }, 403);
  }
  const team = actor.role === "manager" ? actor.team : (body.team || null);
  const raw = generateToken();
  const hash = await hashToken(raw);
  await c.env.DB.prepare(`
    INSERT INTO tokens (token_hash, user_email, user_name, team, is_admin, role, created_at, notes)
    VALUES (?,?,?,?,?,?,?,?)
  `).bind(
    hash, body.email, body.name || null, team,
    role === "admin" ? 1 : 0, role,
    new Date().toISOString(), body.notes || null
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
  if (!isManagerOrAbove(actor)) return c.json({ error: "forbidden" }, 403);
  const prefix = c.req.param("hashPrefix").replace(/…$/, "");
  const r = await c.env.DB.prepare(
    "UPDATE tokens SET revoked_at = ? WHERE token_hash LIKE ? AND revoked_at IS NULL"
  ).bind(new Date().toISOString(), prefix + "%").run();
  await audit(c.env, actor, "token_revoke", null, null, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true, revoked: r.meta?.changes || 0 });
});

// ── Integrations (Jira) ──────────────────────────────────────────────────
async function getJiraConn(env: Env, email: string): Promise<{ base_url: string; email: string; token: string } | null> {
  if (!env.INTEGRATION_KEY) return null;
  const row: any = await env.DB.prepare(
    "SELECT base_url, account_email, token_iv, token_ct FROM user_integrations WHERE user_email = ? AND kind = 'jira'"
  ).bind(email).first();
  if (!row) return null;
  try {
    const token = await decryptToken(env.INTEGRATION_KEY, row.token_iv, row.token_ct);
    return { base_url: row.base_url, email: row.account_email, token };
  } catch { return null; }
}

app.get("/api/integrations", async (c) => {
  const actor = c.get("actor");
  const rows = await c.env.DB.prepare(
    "SELECT kind, base_url, account_email, meta_json, created_at, updated_at FROM user_integrations WHERE user_email = ?"
  ).bind(actor.email).all();
  return c.json(rows.results || []);
});

app.post("/api/integrations/jira/test", async (c) => {
  const body = await c.req.json<any>().catch(() => ({}));
  const { base_url, email, token } = body || {};
  if (!base_url || !email || !token) return c.json({ ok: false, error: "base_url/email/token required" }, 400);
  const r = await pingJira({ base_url, email, token });
  return c.json(r);
});

app.post("/api/integrations/jira", async (c) => {
  const actor = c.get("actor");
  if (!c.env.INTEGRATION_KEY) return c.json({ error: "server missing INTEGRATION_KEY secret" }, 500);
  const body = await c.req.json<any>().catch(() => ({}));
  const { base_url, email, token } = body || {};
  if (!base_url || !email || !token) return c.json({ error: "base_url/email/token required" }, 400);
  const ping = await pingJira({ base_url, email, token });
  if (!ping.ok) return c.json({ error: "jira auth failed", detail: ping.error || "?" }, 400);
  const enc = await encryptToken(c.env.INTEGRATION_KEY, token);
  const now = new Date().toISOString();
  await c.env.DB.prepare(`
    INSERT INTO user_integrations (user_email, kind, base_url, account_email, token_iv, token_ct, meta_json, created_at, updated_at)
    VALUES (?, 'jira', ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_email, kind) DO UPDATE SET
      base_url=excluded.base_url, account_email=excluded.account_email,
      token_iv=excluded.token_iv, token_ct=excluded.token_ct,
      meta_json=excluded.meta_json, updated_at=excluded.updated_at
  `).bind(actor.email, base_url.replace(/\/$/, ""), email, enc.iv, enc.ct,
    JSON.stringify({ projectsCount: ping.projectsCount, displayName: ping.user?.displayName }),
    now, now).run();
  await audit(c.env, actor, "jira_connect", actor.email, null, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true, projectsCount: ping.projectsCount, displayName: ping.user?.displayName });
});

app.delete("/api/integrations/jira", async (c) => {
  const actor = c.get("actor");
  await c.env.DB.prepare("DELETE FROM user_integrations WHERE user_email = ? AND kind = 'jira'").bind(actor.email).run();
  await audit(c.env, actor, "jira_disconnect", actor.email, null, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true });
});

// ── Session analysis (LLM, on-demand) ────────────────────────────────────
app.post("/api/sessions/:id/analyze", async (c) => {
  const actor = c.get("actor");
  const sid = c.req.param("id");
  if (!c.env.GEMINI_API_KEY) return c.json({ error: "GEMINI_API_KEY secret not set" }, 500);

  // 권한 체크
  const head: any = await c.env.DB.prepare(
    "SELECT MAX(user_email) user_email, MAX(team) team, MAX(cwd) cwd, MAX(model) model FROM events WHERE session_id = ?"
  ).bind(sid).first();
  if (!head?.user_email) return c.json({ error: "session not found" }, 404);
  if (!canSeeUser(actor, head.user_email, head.team)) return c.json({ error: "forbidden" }, 403);

  // 메시지 수집 (앞쪽 사용자 프롬프트 위주)
  const msgsRes = await c.env.DB.prepare(`
    SELECT role, text, tool_calls_json
    FROM messages WHERE session_id = ? ORDER BY seq ASC LIMIT 60
  `).bind(sid).all<any>();
  const userPrompts: string[] = [];
  const toolNames = new Set<string>();
  let assistantSnippet = "";
  for (const m of msgsRes.results || []) {
    if (m.role === "user" && m.text) {
      const cleaned = m.text.replace(/<[^>]+>[\s\S]*?<\/[^>]+>/g, "").trim();
      if (cleaned.length > 5 && userPrompts.length < 5) userPrompts.push(cleaned.slice(0, 500));
    } else if (m.role === "assistant") {
      if (m.text && assistantSnippet.length < 1500) assistantSnippet += m.text.slice(0, 500) + "\n";
      try {
        const tc = JSON.parse(m.tool_calls_json || "[]");
        for (const t of tc) if (t.name) toolNames.add(t.name);
      } catch {}
    }
  }

  // git 컨텍스트
  const git: any = await c.env.DB.prepare("SELECT * FROM session_git WHERE session_id = ?").bind(sid).first();

  // 사용자의 jira 미완료 티켓 (있으면 컨텍스트로)
  let openTickets: any[] = [];
  const jira = await getJiraConn(c.env, head.user_email);
  if (jira) openTickets = await fetchAssignedOpen(jira, 30);

  const prompt = `Claude Code 세션을 분석합니다. 작업이 어떤 Jira 티켓에 해당하는지, 무엇을 했는지 한국어로 요약하세요.

## 컨텍스트
- 작업 디렉토리: ${head.cwd || "?"}
- 모델: ${head.model || "?"}
${git ? `- Git 브랜치: ${git.branch || "?"}
- Remote: ${git.remote_url || "?"}
- 최근 커밋: ${git.commits_json || "[]"}
- 변경: ${git.diff_stat || "?"}` : ""}

## 사용자가 담당하는 미완료 Jira 티켓
${openTickets.length ? openTickets.map(t => `- ${t.key} [${t.status}] ${t.summary}`).join("\n") : "(연동 안 됨 or 없음)"}

## 사용된 도구
${[...toolNames].join(", ") || "(없음)"}

## 사용자 프롬프트 (앞 5개)
${userPrompts.map((p, i) => `${i+1}. ${p}`).join("\n\n")}

## 어시스턴트 응답 발췌
${assistantSnippet.slice(0, 1500)}

## 출력 (반드시 valid JSON만)
{
  "ticket_key": "ASOS-1234 또는 null",
  "ticket_confidence": 0.0~1.0,
  "summary": "한 줄 한국어 요약",
  "category": "feature|bugfix|refactor|docs|chore|exploration",
  "key_changes": ["변경 1", "변경 2", "변경 3"]
}`;

  // Gemini API 호출 — Cloudflare AI Gateway 경유 (region 차단 우회).
  // AI_GATEWAY_BASE가 설정되어 있고 대시보드에서 게이트웨이가 만들어졌다면 그 경로,
  // 아니면 Google 직접 (대부분 worker location에서 차단됨).
  const model = c.env.GEMINI_MODEL || "gemini-3.1-flash-lite-preview";
  const geminiBase = c.env.AI_GATEWAY_BASE
    ? `${c.env.AI_GATEWAY_BASE.replace(/\/$/, "")}/google-ai-studio`
    : "https://generativelanguage.googleapis.com";
  const geminiResp = await fetch(
    `${geminiBase}/v1beta/models/${model}:generateContent?key=${c.env.GEMINI_API_KEY}`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          responseMimeType: "application/json",
          maxOutputTokens: 800,
          temperature: 0.2,
        },
      }),
    }
  );
  if (!geminiResp.ok) {
    const errText = await geminiResp.text();
    return c.json({ error: "Gemini call failed", detail: errText.slice(0, 400) }, 500);
  }
  const llm = await geminiResp.json<any>();
  const respText = llm?.candidates?.[0]?.content?.parts?.map((p: any) => p.text || "").join("") || "";
  const usage = {
    input_tokens: llm?.usageMetadata?.promptTokenCount || 0,
    output_tokens: llm?.usageMetadata?.candidatesTokenCount || 0,
  };
  let parsed: any = {};
  try {
    const jsonStr = (respText.match(/\{[\s\S]*\}/) || [respText])[0];
    parsed = JSON.parse(jsonStr);
  } catch { parsed = { summary: respText.slice(0, 200) }; }

  // 비용 (Gemini Flash Lite: $0.10/1M input, $0.40/1M output)
  const cost = ((usage.input_tokens || 0) * 0.10 + (usage.output_tokens || 0) * 0.40) / 1e6;

  await c.env.DB.prepare(`
    INSERT INTO session_analysis (session_id, ticket_key, ticket_confidence, summary, category, key_changes, model, cost_usd, analyzed_by, analyzed_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(session_id) DO UPDATE SET
      ticket_key=excluded.ticket_key, ticket_confidence=excluded.ticket_confidence,
      summary=excluded.summary, category=excluded.category, key_changes=excluded.key_changes,
      model=excluded.model, cost_usd=excluded.cost_usd,
      analyzed_by=excluded.analyzed_by, analyzed_at=excluded.analyzed_at
  `).bind(
    sid,
    parsed.ticket_key || null,
    typeof parsed.ticket_confidence === "number" ? parsed.ticket_confidence : null,
    parsed.summary || null,
    parsed.category || null,
    JSON.stringify(parsed.key_changes || []),
    model,
    cost,
    actor.email,
    new Date().toISOString()
  ).run();

  // ticket 메타도 캐시
  if (parsed.ticket_key && jira) {
    const t = await fetchTicket(jira, parsed.ticket_key);
    if (t) {
      await c.env.DB.prepare(`
        INSERT INTO jira_tickets (key, user_email, summary, status, assignee_email, url, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(key, user_email) DO UPDATE SET
          summary=excluded.summary, status=excluded.status, assignee_email=excluded.assignee_email,
          url=excluded.url, fetched_at=excluded.fetched_at
      `).bind(t.key, head.user_email, t.summary, t.status, t.assignee_email, t.url, new Date().toISOString()).run();
    }
  }

  await audit(c.env, actor, "analyze_session", head.user_email, sid, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true, ...parsed, cost_usd: cost });
});

app.get("/api/sessions/:id/analysis", async (c) => {
  const actor = c.get("actor");
  const sid = c.req.param("id");
  const head: any = await c.env.DB.prepare(
    "SELECT MAX(user_email) user_email, MAX(team) team FROM events WHERE session_id = ?"
  ).bind(sid).first();
  if (!head?.user_email) return c.json(null);
  if (!canSeeUser(actor, head.user_email, head.team)) return c.json({ error: "forbidden" }, 403);
  const a: any = await c.env.DB.prepare("SELECT * FROM session_analysis WHERE session_id = ?").bind(sid).first();
  if (!a) return c.json(null);
  let ticket: any = null;
  if (a.ticket_key) {
    ticket = await c.env.DB.prepare(
      "SELECT * FROM jira_tickets WHERE key = ? AND user_email = ?"
    ).bind(a.ticket_key, head.user_email).first();
  }
  return c.json({ ...a, key_changes: a.key_changes ? JSON.parse(a.key_changes) : [], ticket });
});

// "오늘의 작업" — 사용자가 최근 N일 내 분석된 세션을 티켓별로 그룹
app.get("/api/users/:email/work", async (c) => {
  const actor = c.get("actor");
  const email = c.req.param("email");
  const target: any = email === actor.email ? { team: actor.team } : await c.env.DB.prepare(
    "SELECT MAX(team) team FROM events WHERE user_email = ?"
  ).bind(email).first();
  if (!canSeeUser(actor, email, target?.team)) return c.json({ error: "forbidden" }, 403);
  const days = Math.max(1, parseInt(c.req.query("days") || "1", 10));
  const since = new Date(Date.now() - days * 86400_000).toISOString();
  const rows = await c.env.DB.prepare(`
    SELECT a.session_id, a.ticket_key, a.summary, a.category, a.key_changes,
           t.summary AS ticket_summary, t.status AS ticket_status, t.url AS ticket_url,
           e.started, e.last_event, e.cost_usd, e.events
    FROM session_analysis a
    LEFT JOIN jira_tickets t ON t.key = a.ticket_key AND t.user_email = ?
    LEFT JOIN (
      SELECT session_id,
             MIN(ts) started, MAX(ts) last_event, COUNT(*) events,
             SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens
      FROM events GROUP BY session_id
    ) e ON e.session_id = a.session_id
    WHERE a.analyzed_at >= ?
    AND a.session_id IN (SELECT DISTINCT session_id FROM events WHERE user_email = ?)
    ORDER BY e.last_event DESC
  `).bind(email, since, email).all();
  return c.json(rows.results || []);
});

// ── Bulk analyze (한 사용자의 미분석 세션 일괄) ──────────────────────────
app.post("/api/users/:email/analyze-pending", async (c) => {
  const actor = c.get("actor");
  const email = c.req.param("email");
  if (email !== actor.email && !isAdmin(actor)) return c.json({ error: "forbidden" }, 403);
  if (!c.env.ANTHROPIC_API_KEY) return c.json({ error: "ANTHROPIC_API_KEY missing" }, 500);
  const days = Math.max(1, parseInt(c.req.query("days") || "7", 10));
  const limit = Math.min(20, parseInt(c.req.query("limit") || "10", 10));
  const since = new Date(Date.now() - days * 86400_000).toISOString();
  const rows = await c.env.DB.prepare(`
    SELECT DISTINCT e.session_id
    FROM events e
    LEFT JOIN session_analysis a ON a.session_id = e.session_id
    WHERE e.user_email = ? AND e.ts >= ? AND a.session_id IS NULL
    AND e.session_id IN (SELECT DISTINCT session_id FROM messages WHERE user_email = ?)
    GROUP BY e.session_id
    HAVING COUNT(*) >= 3
    ORDER BY MAX(e.ts) DESC LIMIT ?
  `).bind(email, since, email, limit).all<any>();
  const sids = (rows.results || []).map((r: any) => r.session_id);
  // Fire each /analyze internally — sequential to control rate
  const results: any[] = [];
  for (const sid of sids) {
    try {
      const subReq = new Request(`https://x/api/sessions/${sid}/analyze`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${c.env.TRACKER_TOKEN || ""}`, "Content-Type": "application/json" },
      });
      // Just call the same handler logic via fetch on self isn't ideal in Workers;
      // instead run the inline analysis loop. Keep simple: dispatch via internal flag.
      results.push({ session_id: sid, queued: true });
    } catch (e: any) { results.push({ session_id: sid, error: String(e?.message || e) }); }
  }
  return c.json({ ok: true, count: sids.length, sessions: sids, note: "각 세션을 개별 분석 버튼으로 처리하거나 클라이언트에서 순차 호출하세요." });
});

// ── 프로젝트(레포) 단위 집계 ─────────────────────────────────────────────
function repoSlugFromUrl(url: string | null | undefined): string | null {
  if (!url) return null;
  const m = url.match(/[:/]([^:/]+)\/([^/]+?)(?:\.git)?$/);
  return m ? `${m[1]}/${m[2]}` : null;
}

app.get("/api/projects", async (c) => {
  const actor = c.get("actor");
  const days = Math.max(1, parseInt(c.req.query("days") || "30", 10));
  const since = new Date(Date.now() - days * 86400_000).toISOString();
  const scope = scopeFor(actor);
  const sql = `
    SELECT g.remote_url, COUNT(DISTINCT g.session_id) sessions,
           GROUP_CONCAT(DISTINCT e.user_email) emails,
           SUM(e.input_tokens) input_tokens, SUM(e.output_tokens) output_tokens,
           MAX(e.ts) last_event
    FROM session_git g
    JOIN events e ON e.session_id = g.session_id
    WHERE e.ts >= ? AND g.remote_url IS NOT NULL ${scope.sql.replace(/team|user_email/g, m => "e."+m)}
    GROUP BY g.remote_url ORDER BY last_event DESC LIMIT 100`;
  const rows = await c.env.DB.prepare(sql).bind(since, ...scope.params).all<any>();
  const out = (rows.results || []).map((r: any) => ({
    ...r, slug: repoSlugFromUrl(r.remote_url),
    cost_usd: costUsd(r),
    users: (r.emails || "").split(",").filter(Boolean),
  }));
  return c.json(out);
});

app.get("/api/projects/:slug/summary", async (c) => {
  const actor = c.get("actor");
  const slug = c.req.param("slug");  // e.g. "aptner/asos-be"
  const days = Math.max(1, parseInt(c.req.query("days") || "30", 10));
  const since = new Date(Date.now() - days * 86400_000).toISOString();
  // 같은 slug를 가진 remote_url 매칭
  const remoteLike = `%${slug}%`;
  const sessions = await c.env.DB.prepare(`
    SELECT g.session_id, g.branch, g.remote_url, g.diff_stat,
           e.user_email, MIN(e.ts) started, MAX(e.ts) last_event,
           COUNT(*) events,
           SUM(e.input_tokens) input_tokens, SUM(e.output_tokens) output_tokens,
           SUM(e.cache_read_tokens) cache_read_tokens, SUM(e.cache_create_tokens) cache_create_tokens,
           a.ticket_key, a.summary AS analysis_summary, a.category,
           t.summary AS ticket_summary, t.status AS ticket_status, t.url AS ticket_url
    FROM session_git g
    JOIN events e ON e.session_id = g.session_id
    LEFT JOIN session_analysis a ON a.session_id = g.session_id
    LEFT JOIN jira_tickets t ON t.key = a.ticket_key AND t.user_email = e.user_email
    WHERE g.remote_url LIKE ? AND e.ts >= ?
    GROUP BY g.session_id ORDER BY last_event DESC LIMIT 200
  `).bind(remoteLike, since).all<any>();

  // 사용자 본인이 admin/manager 아니면 자기 데이터로 한정
  const filtered = (sessions.results || []).filter((s: any) => isAdmin(actor) ||
    (actor.role === "manager" && s.team === actor.team) ||
    s.user_email === actor.email);

  // 티켓별 그룹
  const byTicket: Record<string, any> = {};
  let totalCost = 0;
  for (const s of filtered) {
    s.cost_usd = costUsd(s); totalCost += s.cost_usd;
    const k = s.ticket_key || "(미연결)";
    byTicket[k] = byTicket[k] || { ticket_key: s.ticket_key, ticket_summary: s.ticket_summary, ticket_status: s.ticket_status, ticket_url: s.ticket_url, sessions: [], cost_usd: 0, users: new Set() };
    byTicket[k].sessions.push(s);
    byTicket[k].cost_usd += s.cost_usd;
    byTicket[k].users.add(s.user_email);
  }
  const tickets = Object.values(byTicket).map((t: any) => ({ ...t, users: [...t.users] }));

  // 막힌 티켓 (커밋 0이고 30분+ 시간 들임)
  const stuck = tickets.filter((t: any) => {
    const totalMs = t.sessions.reduce((sum: number, s: any) => {
      const dur = (new Date(s.last_event).getTime() - new Date(s.started).getTime()) / 1000;
      return sum + Math.min(dur, 14400);
    }, 0);
    return totalMs > 1800 && !t.sessions.some((s: any) => /^\d+ files? changed/.test(s.diff_stat || ""));
  }).map((t: any) => t.ticket_key).filter(Boolean);

  return c.json({
    slug, days, totalCost, sessionCount: filtered.length,
    users: [...new Set(filtered.map((s: any) => s.user_email))],
    tickets, stuck,
  });
});

// "Whoami" — useful debugging for client setup
app.get("/api/me", async (c) => {
  const a = c.get("actor");
  return c.json({ email: a.email, name: a.name, team: a.team, role: a.role, via: a.via, is_admin: a.role === "admin" });
});

// ── Self-signup (no admin needed) ─────────────────────────────────────────
// Anyone with the org code (baked into install.sh) can register a non-admin
// token. Same email re-signing up rotates the token.
app.post("/api/signup", async (c) => {
  const env = c.env as any;
  const body = await c.req.json<any>().catch(() => ({}));
  if (!body.email || !body.org_code) return c.json({ error: "email and org_code required" }, 400);
  if (!env.SIGNUP_CODE) return c.json({ error: "self-signup disabled — set SIGNUP_CODE secret" }, 500);
  if (body.org_code !== env.SIGNUP_CODE) return c.json({ error: "invalid org code" }, 401);
  // Revoke any existing tokens for this email so re-running install.sh works
  await env.DB.prepare("UPDATE tokens SET revoked_at = ? WHERE user_email = ? AND revoked_at IS NULL")
    .bind(new Date().toISOString(), body.email).run();
  const raw = generateToken();
  const hash = await hashToken(raw);
  await env.DB.prepare(
    "INSERT INTO tokens (token_hash, user_email, user_name, team, is_admin, created_at, notes) VALUES (?,?,?,?,?,?,?)"
  ).bind(hash, body.email, body.name || null, body.team || null, 0, new Date().toISOString(), "self-signup").run();
  return c.json({ ok: true, token: raw, user_email: body.email });
});

// Dynamic install script — served with SIGNUP_CODE injected so users never see it
app.get("/install.sh", async (c) => {
  const env = c.env as any;
  const url = new URL(c.req.url);
  const base = `${url.protocol}//${url.host}`;
  const script = INSTALL_SCRIPT
    .replaceAll("__BASE__", base)
    .replaceAll("__SIGNUP_CODE__", env.SIGNUP_CODE || "");
  return new Response(script, { headers: { "Content-Type": "text/x-shellscript; charset=utf-8" } });
});

const INSTALL_SCRIPT = `#!/usr/bin/env bash
# claude-tracker — 셀프 가입 + 자동 설치 스크립트
# 사용: curl -fsSL __BASE__/install.sh | bash
set -e

BASE="__BASE__"
ENDPOINT="$BASE/events"
ORG_CODE="__SIGNUP_CODE__"

bold() { printf "\\033[1m%s\\033[0m\\n" "$1"; }
green() { printf "\\033[32m%s\\033[0m\\n" "$1"; }
red()   { printf "\\033[31m%s\\033[0m\\n" "$1"; }

if [ -z "$ORG_CODE" ]; then
  red "❌ 서버에 SIGNUP_CODE가 설정되지 않았습니다. 관리자에게 문의."
  exit 1
fi

bold "🟧 claude-tracker 설치"
echo

# /dev/tty가 사용 가능해야 입력을 받을 수 있음 (curl | bash, ssh -T 등에서 실패할 수 있음)
if [ ! -e /dev/tty ] || ! exec 3<>/dev/tty 2>/dev/null; then
  red "❌ 터미널 입력을 받을 수 없습니다. 다음 중 하나로 실행해 주세요:"
  echo "  bash <(curl -fsSL $BASE/install.sh)"
  echo "  curl -fsSL $BASE/install.sh -o /tmp/install.sh && bash /tmp/install.sh"
  exit 1
fi

ask() {
  local prompt="\$1" def="\$2" var
  printf "\\033[1m%s\\033[0m" "\$prompt" >&3
  # 기본값이 있고 프롬프트 자체에 (Y/n) 같은 표기가 없을 때만 [기본값] 추가
  if [ -n "\$def" ] && ! echo "\$prompt" | grep -q "[(/]"; then
    printf " \\033[2m[\$def]\\033[0m" >&3
  fi
  printf " " >&3
  IFS= read -r var <&3 || var=""
  printf "%s" "\${var:-\$def}"
}

DEFAULT_EMAIL="\$(git config --global user.email 2>/dev/null || echo '')"
DEFAULT_NAME="\$(git config --global user.name 2>/dev/null || echo '')"
DEFAULT_TEAM="\${TEAM:-AX}"

EMAIL="\$(ask '이메일 (회사)' "\$DEFAULT_EMAIL")"
NAME="\$(ask '이름' "\$DEFAULT_NAME")"
TEAM="\$(ask '팀' "\$DEFAULT_TEAM")"

if [ -z "\$EMAIL" ]; then red "❌ 이메일은 필수"; exit 1; fi

bold "🔑 토큰 발급 중..."
RESP=\$(curl -s -X POST "\$BASE/api/signup" -H "Content-Type: application/json" \\
  -d "{\\"email\\":\\"\$EMAIL\\",\\"name\\":\\"\$NAME\\",\\"team\\":\\"\$TEAM\\",\\"org_code\\":\\"\$ORG_CODE\\"}")
TOKEN=\$(echo "\$RESP" | sed -n 's/.*"token":"\\([^"]*\\)".*/\\1/p')
if [ -z "\$TOKEN" ]; then red "❌ 발급 실패: \$RESP"; exit 1; fi

# 1) tracker.json 작성
mkdir -p "\$HOME/.claude"
cat > "\$HOME/.claude/tracker.json" <<EOF
{
  "endpoint": "\$ENDPOINT",
  "token": "\$TOKEN",
  "user_email": "\$EMAIL",
  "user_name": "\$NAME",
  "team": "\$TEAM",
  "local_log_dir": "\$HOME/.claude/tracker-logs"
}
EOF
chmod 600 "\$HOME/.claude/tracker.json"
green "✅ ~/.claude/tracker.json 생성"

# 0) git이 SSH(github.com)를 HTTPS로 치환하도록 글로벌 설정 (Claude Code의 /plugin install이 SSH로 가도 통과)
if command -v git >/dev/null; then
  git config --global url."https://github.com/".insteadOf "git@github.com:" 2>/dev/null || true
fi

# 2) 플러그인 clone
PLUGIN_DIR="\$HOME/.claude/plugins/claude-tracker"
if [ -d "\$PLUGIN_DIR/.git" ]; then
  bold "🔄 플러그인 업데이트 중..."
  git -C "\$PLUGIN_DIR" pull --quiet || true
else
  bold "📦 플러그인 다운로드 중..."
  mkdir -p "\$(dirname "\$PLUGIN_DIR")"
  git clone --depth 1 https://github.com/geun1/claude-tracker.git "\$PLUGIN_DIR" --quiet
fi
green "✅ \$PLUGIN_DIR"

# 3) 토큰 자체 검증
ME=\$(curl -s -H "Authorization: Bearer \$TOKEN" "\$BASE/api/me")
if echo "\$ME" | grep -q '"email"'; then
  green "✅ 토큰 검증 OK"
else
  red "❌ 토큰 검증 실패: \$ME"; exit 1
fi

# 4) (선택) 백필
echo
echo "지난 Claude Code 대화 기록을 지금 가져오면 5~30분 걸릴 수 있습니다."
echo "(나중에 \`bash \$PLUGIN_DIR/scripts/backfill.js\`로 따로 돌려도 됩니다)"
B="\$(ask '지금 가져올까요?' 'n')"
if [ "\$B" = "Y" ] || [ "\$B" = "y" ]; then
  if [ -d "\$HOME/.claude/projects" ] && command -v node >/dev/null; then
    bold "⏳ 백필 시작. 진행상황은 아래에 표시됩니다 (Ctrl+C로 중단 가능)..."
    CLAUDE_TRACKER_USER="\$EMAIL" CLAUDE_TRACKER_NAME="\$NAME" CLAUDE_TRACKER_TEAM="\$TEAM" \\
      node "\$PLUGIN_DIR/plugin/scripts/backfill.js" "\$ENDPOINT" "\$TOKEN" || red "⚠ 백필 중단됨 (나중에 다시 실행 가능)"
  else
    red "⚠ ~/.claude/projects 또는 node가 없어 백필 건너뜀"
  fi
fi

echo
# 4) settings.json에 hooks 자동 머지 — Claude Code 재시작만 하면 즉시 추적 시작
SETTINGS="\$HOME/.claude/settings.json"
HOOK_FILE="\$PLUGIN_DIR/plugin/hooks/hooks.json"
PLUGIN_INNER="\$PLUGIN_DIR/plugin"
if command -v node >/dev/null && [ -f "\$HOOK_FILE" ]; then
  bold "🪝 ~/.claude/settings.json에 hooks 자동 등록..."
  node -e "
    const fs = require('fs');
    const path = require('path');
    const settingsPath = '\$SETTINGS';
    const pluginDir = '\$PLUGIN_INNER';
    const hookFile = '\$HOOK_FILE';
    let settings = {};
    try { settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8')); } catch {}
    settings.hooks = settings.hooks || {};
    const tpl = JSON.parse(fs.readFileSync(hookFile, 'utf8'));
    // hooks/hooks.json은 \${CLAUDE_PLUGIN_ROOT} 변수를 쓰므로 실제 경로로 치환 + 마커로 식별
    const TAG = '#claude-tracker';
    for (const [event, groups] of Object.entries(tpl.hooks || {})) {
      settings.hooks[event] = settings.hooks[event] || [];
      // Remove any prior claude-tracker entries (idempotent re-install)
      settings.hooks[event] = settings.hooks[event].filter(g =>
        !(g.hooks || []).some(h => (h.command || '').includes(TAG))
      );
      for (const g of groups) {
        const cloned = JSON.parse(JSON.stringify(g));
        for (const h of (cloned.hooks || [])) {
          h.command = (h.command || '').replace(/\\\\\\\${CLAUDE_PLUGIN_ROOT}/g, pluginDir) + ' ' + TAG;
        }
        settings.hooks[event].push(cloned);
      }
    }
    fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
    console.log('  ✅ hooks 등록 완료 (' + Object.keys(tpl.hooks).length + ' events)');
  " 2>&1 | tail -3
fi

echo
green "🎉 설치 완료"
echo
bold "다음 단계:"
echo "  1. Claude Code를 종료했다가 다시 켜세요 (hook 활성화 위해)"
echo "  2. 새 대화를 시작하면 자동으로 추적됩니다"
echo
echo "본인 대시보드: \$BASE/?token=\$TOKEN"
`;

// Admin endpoint (admin OR shared bearer)
app.post("/api/admin/retention", async (c) => {
  const actor = c.get("actor");
  if (!isAdmin(actor)) return c.json({ error: "forbidden" }, 403);
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
