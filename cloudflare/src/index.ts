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
import { pingJira, fetchTicket, fetchAssignedOpen, fetchTicketContext, addComment, getTransitions, doTransition } from "./jira";
import { runOptimize, aggregateModelStats, compareModels } from "./optimize";
import { fetchConfluenceForTicket, createConfluencePage, addJiraRemoteLink, listConfluenceSpaces, deleteConfluencePage, removeJiraRemoteLinkByUrl, getPersonalSpaceKey, findTicketWikiPage, updateConfluencePageBody, ensureEpicPage } from "./confluence";
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
// HTML/JS는 자주 갱신되므로 브라우저가 매번 revalidate 하도록 no-store.
// (icons.svg/loader.js만 즉시 캐시 무효화 — 자주 안 바뀌면 immutable로 바꿀 수 있음)
async function freshAsset(c: any, urlPath: string) {
  const r = await c.env.ASSETS.fetch(new Request(new URL(urlPath, c.req.url)));
  const headers = new Headers(r.headers);
  headers.set("Cache-Control", "no-store, must-revalidate");
  return new Response(r.body, { status: r.status, headers });
}
app.get("/", (c) => freshAsset(c, "/home.html"));
app.get("/browse", (c) => freshAsset(c, "/sessions.html"));
app.get("/u/:email", (c) => freshAsset(c, "/profile.html"));
app.get("/t/:team", (c) => freshAsset(c, "/team.html"));
app.get("/g/:gid", (c) => freshAsset(c, "/group.html"));
app.get("/p/:slug{.+}", (c) => freshAsset(c, "/project.html"));
app.get("/project.html", (c) => freshAsset(c, "/project.html"));
app.get("/dashboard.html", (c) => freshAsset(c, "/dashboard.html"));
app.get("/sessions.html", (c) => freshAsset(c, "/sessions.html"));
app.get("/profile.html", (c) => freshAsset(c, "/profile.html"));
app.get("/team.html", (c) => freshAsset(c, "/team.html"));
app.get("/home.html", (c) => freshAsset(c, "/home.html"));
app.get("/loader.js", (c) => freshAsset(c, "/loader.js"));
app.get("/icons.svg", (c) => freshAsset(c, "/icons.svg"));
app.get("/health", (c) => c.json({ ok: true, environment: (c.env as any).ENVIRONMENT || "unknown" }));
app.get("/favicon.ico", () => new Response(null, { status: 204 }));

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

  // Auto-scan session quality on session_end. Best-effort; runs after response
  // sent via waitUntil. Idempotent (ON CONFLICT UPDATE) so re-scans are safe.
  if (b.event === "session_end" && b.session_id) {
    c.executionCtx.waitUntil(autoScanSession(c.env, b.session_id));
  }

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
  const byTeam: Record<string, any> = {};
  for (const r of (rowsRes.results || []) as any[]) byTeam[r.team] = { ...r, cost_usd: cby[r.team] || 0 };
  // 레지스트리 팀(멤버 0명 포함) 머지 — sort_order 보존
  let registry: any[] = [];
  try {
    const reg = await c.env.DB.prepare("SELECT name, sort_order FROM teams ORDER BY sort_order ASC, name ASC").all<any>();
    registry = reg.results || [];
  } catch {}
  for (const r of registry) {
    if (!byTeam[r.name]) byTeam[r.name] = {
      team: r.name, users: 0, sessions: 0,
      input_tokens: 0, output_tokens: 0, cache_read_tokens: 0, cache_create_tokens: 0,
      cost_usd: 0, sort_order: r.sort_order,
    };
    else byTeam[r.name].sort_order = r.sort_order;
  }
  const rows = Object.values(byTeam).sort((a: any, b: any) => {
    const ao = a.sort_order ?? 9999, bo = b.sort_order ?? 9999;
    if (ao !== bo) return ao - bo;
    return (b.input_tokens + b.output_tokens) - (a.input_tokens + a.output_tokens);
  });
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

// Debug: 본인 Jira 미완료 티켓 미리보기 (LLM 컨텍스트로 들어가는 그 목록)
app.get("/api/integrations/jira/tickets", async (c) => {
  const actor = c.get("actor");
  const conn = await getJiraConn(c.env, actor.email);
  if (!conn) return c.json({ ok: false, error: "no jira connection saved" });
  const tickets = await fetchAssignedOpen(conn, 50);
  return c.json({ ok: true, base_url: conn.base_url, count: tickets.length, tickets });
});

// Debug: Jira 토큰의 raw API 권한 진단
app.get("/api/integrations/jira/diag", async (c) => {
  const actor = c.get("actor");
  const conn = await getJiraConn(c.env, actor.email);
  if (!conn) return c.json({ error: "no jira connection saved" });
  const auth = `Basic ${btoa(`${conn.email}:${conn.token}`)}`;
  const headers = { Authorization: auth, Accept: "application/json" };
  const url = conn.base_url.replace(/\/$/, "");
  const out: any = { base_url: url };
  // 1) myself
  try { const r = await fetch(`${url}/rest/api/3/myself`, { headers }); out.myself = { status: r.status, body: r.ok ? await r.json() : await r.text() }; }
  catch (e: any) { out.myself = { error: String(e?.message) }; }
  // 2) project list
  try { const r = await fetch(`${url}/rest/api/3/project/search?maxResults=20`, { headers });
    const j = r.ok ? await r.json<any>() : null;
    out.projects = { status: r.status, count: j?.total, sample: (j?.values || []).slice(0,5).map((p: any) => p.key) }; }
  catch (e: any) { out.projects = { error: String(e?.message) }; }
  // 3) JQL: assignee currentUser
  for (const jql of [
    "assignee = currentUser()",
    "assignee = currentUser() AND statusCategory != Done",
    "reporter = currentUser()",
    "updated >= -30d",
  ]) {
    try {
      const r = await fetch(`${url}/rest/api/3/search/jql`, {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ jql, maxResults: 3, fields: ["summary", "status", "assignee"] }),
      });
      const t = await r.text();
      let body: any = null; try { body = JSON.parse(t); } catch { body = t.slice(0, 200); }
      out[`jql_${jql.replace(/\W+/g, "_").slice(0, 30)}`] = { status: r.status, total: body?.total ?? null, sample: (body?.issues || []).slice(0,2).map((i: any) => ({ key: i.key, status: i.fields?.status?.name })) };
    } catch (e: any) { out[`jql_err`] = String(e?.message); }
  }
  return c.json(out);
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
  if (jira) openTickets = await fetchAssignedOpen(jira, 80);

  // ── Pre-extract: regex로 prompt/branch/commit에서 키 직접 추출 ──────────
  // 환각 방지 + LLM이 빠뜨리는 케이스 보강.
  const KEY_RE = /\b([A-Z][A-Z0-9]{1,9}-\d+)\b/g;
  const regexHits: { key: string; evidence: string }[] = [];
  const seenRx = new Set<string>();
  const addHit = (k: string, ev: string) => {
    const up = k.toUpperCase();
    if (seenRx.has(up)) return;
    seenRx.add(up);
    regexHits.push({ key: up, evidence: ev });
  };
  for (let i = 0; i < userPrompts.length; i++) {
    for (const m of userPrompts[i].matchAll(KEY_RE)) addHit(m[1], `prompt:${i+1}`);
  }
  if (git?.branch) for (const m of git.branch.matchAll(KEY_RE)) addHit(m[1], "branch");
  if (git?.commits_json) {
    try {
      const cm = JSON.parse(git.commits_json) || [];
      for (const c0 of cm) for (const m of String(c0.msg || "").matchAll(KEY_RE)) addHit(m[1], `commit:${(c0.sha || "").slice(0,7)}`);
    } catch {}
  }

  // 수동 매칭(source='manual')은 보존 — 분석으로 덮어쓰지 않음
  const manualRows = await c.env.DB.prepare(
    "SELECT ticket_key, evidence, confidence FROM session_tickets WHERE session_id = ? AND source = 'manual'"
  ).bind(sid).all<any>();
  const manualKeys = new Set((manualRows.results || []).map((r: any) => r.ticket_key));

  const prompt = `Claude Code 세션을 분석합니다. 작업이 어떤 Jira 티켓에 해당하는지, 무엇을 했는지 한국어로 요약하세요.

## 컨텍스트
- 작업 디렉토리: ${head.cwd || "?"}
- 모델: ${head.model || "?"}
${git ? `- Git 브랜치: ${git.branch || "?"}
- Remote: ${git.remote_url || "?"}
- 최근 커밋: ${git.commits_json || "[]"}
- 변경: ${git.diff_stat || "?"}` : ""}

## 사용자가 담당하는 미완료 Jira 티켓 (이 안에서만 고르세요)
${openTickets.length ? openTickets.map(t => `- ${t.key} [${t.status}] ${t.summary}`).join("\n") : "(연동 안 됨 or 없음)"}

## 코드/메시지에서 자동 추출된 티켓 키 (참고; 모두 이미 후보로 포함됨)
${regexHits.length ? regexHits.map(h => `- ${h.key}  (출처: ${h.evidence})`).join("\n") : "(없음)"}

## 사용된 도구
${[...toolNames].join(", ") || "(없음)"}

## 사용자 프롬프트 (앞 5개)
${userPrompts.map((p, i) => `${i+1}. ${p}`).join("\n\n")}

## 어시스턴트 응답 발췌
${assistantSnippet.slice(0, 1500)}

## 출력 규칙
- 한 세션에서 여러 티켓에 걸쳐 작업했다면 \`tickets\`에 모두 포함하세요 (관련도 높은 순).
- 위에 나열된 후보(미완료 + 자동추출) 안에서만 고르세요. 새 키를 환각으로 만들지 마세요.
- 각 티켓별로 작업 비중(weight)을 합 1.0이 되도록 추정하세요.
- 각 티켓에 대한 \`summary\`(1~2줄)와 \`key_changes\`(2~4개)를 그 티켓에 해당하는 작업만으로 구체적으로 작성하세요.
- 최상위 \`summary\`는 세션 전체 한 줄 헤드라인 (모든 티켓 통합), \`key_changes\`는 세션 전체 핵심 변경 3~5개.

## 출력 (반드시 valid JSON만)
{
  "tickets": [
    {
      "key": "ASOS-1234",
      "confidence": 0.0~1.0,
      "weight": 0.0~1.0,
      "evidence": "왜 이 티켓인지 한 줄",
      "summary": "이 티켓에 대해 한 일 1~2줄",
      "key_changes": ["이 티켓 한정 변경 1", "변경 2"]
    }
  ],
  "summary": "세션 전체 한 줄 헤드라인",
  "category": "feature|bugfix|refactor|docs|chore|exploration",
  "key_changes": ["전체 변경 1", "전체 변경 2", "전체 변경 3"]
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

  // 정규화: LLM의 tickets[] + regex hits + 미완료 후보 교차 검증
  const candidateSet = new Set<string>([
    ...openTickets.map((t: any) => String(t.key).toUpperCase()),
    ...regexHits.map(h => h.key),
  ]);
  type Linked = { key: string; confidence: number; weight: number; evidence: string; source: "llm"|"regex"|"branch"; summary: string|null; key_changes: string[] };
  const linkedMap = new Map<string, Linked>();
  // (a) regex hits — 강한 신호 (commit/branch는 신뢰도 0.9, prompt는 0.7)
  for (const h of regexHits) {
    const isStrong = h.evidence.startsWith("branch") || h.evidence.startsWith("commit");
    const src: Linked["source"] = h.evidence.startsWith("branch") ? "branch" : "regex";
    linkedMap.set(h.key, { key: h.key, confidence: isStrong ? 0.9 : 0.7, weight: 0, evidence: h.evidence, source: src, summary: null, key_changes: [] });
  }
  // (b) LLM tickets — candidate set 안에 있는 것만 채택, 없으면 무시(환각 방지)
  const llmList = Array.isArray(parsed.tickets) ? parsed.tickets : [];
  for (const t of llmList) {
    if (!t || typeof t.key !== "string") continue;
    const key = t.key.toUpperCase();
    if (!candidateSet.has(key)) continue;  // 환각 차단
    const conf = typeof t.confidence === "number" ? Math.max(0, Math.min(1, t.confidence)) : 0.5;
    const w = typeof t.weight === "number" ? Math.max(0, t.weight) : 0;
    const ev = t.evidence ? String(t.evidence).slice(0, 200) : "llm";
    const sm = typeof t.summary === "string" ? t.summary.slice(0, 500) : null;
    const kc = Array.isArray(t.key_changes) ? t.key_changes.filter((x: any) => typeof x === "string").slice(0, 6) : [];
    const prev = linkedMap.get(key);
    if (prev) {
      prev.weight = w || prev.weight;
      prev.confidence = Math.max(prev.confidence, conf);
      prev.evidence = `${prev.evidence}; llm:${ev}`;
      prev.summary = sm || prev.summary;
      if (kc.length) prev.key_changes = kc;
    } else {
      linkedMap.set(key, { key, confidence: conf, weight: w, evidence: `llm:${ev}`, source: "llm", summary: sm, key_changes: kc });
    }
  }
  // weight 정규화: 합 1.0; 모두 0이면 균등 분배
  const linked = Array.from(linkedMap.values()).slice(0, 8);
  const sumW = linked.reduce((s, x) => s + (x.weight || 0), 0);
  if (sumW <= 0 && linked.length) {
    for (const x of linked) x.weight = 1 / linked.length;
  } else if (sumW > 0) {
    for (const x of linked) x.weight = (x.weight || 0) / sumW;
  }
  // confidence 높은 순 정렬, primary는 첫 번째
  linked.sort((a, b) => b.confidence - a.confidence);
  const ticketKeys = linked.map(x => x.key);
  const primaryKey = ticketKeys[0] || null;
  const primaryConf = linked[0]?.confidence ?? null;

  // session_analysis: 호환 컬럼은 계속 채우되, 진짜 진실은 session_tickets
  await c.env.DB.prepare(`
    INSERT INTO session_analysis (session_id, ticket_key, ticket_keys, ticket_confidence, summary, category, key_changes, model, cost_usd, analyzed_by, analyzed_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(session_id) DO UPDATE SET
      ticket_key=excluded.ticket_key, ticket_keys=excluded.ticket_keys, ticket_confidence=excluded.ticket_confidence,
      summary=excluded.summary, category=excluded.category, key_changes=excluded.key_changes,
      model=excluded.model, cost_usd=excluded.cost_usd,
      analyzed_by=excluded.analyzed_by, analyzed_at=excluded.analyzed_at
  `).bind(
    sid,
    primaryKey,
    ticketKeys.length ? JSON.stringify(ticketKeys) : null,
    primaryConf,
    parsed.summary || null,
    parsed.category || null,
    JSON.stringify(parsed.key_changes || []),
    model, cost, actor.email, new Date().toISOString()
  ).run();

  // session_tickets: manual은 보존, 비-manual만 재작성
  await c.env.DB.prepare("DELETE FROM session_tickets WHERE session_id = ? AND source <> 'manual'").bind(sid).run();
  const now = new Date().toISOString();
  let rank = 0;
  for (const x of linked) {
    if (manualKeys.has(x.key)) continue;  // manual이 이미 있으면 자동 매칭으로 덮지 않음
    await c.env.DB.prepare(`
      INSERT OR REPLACE INTO session_tickets
        (session_id, ticket_key, rank, confidence, evidence, source, weight, summary, key_changes, created_by, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(sid, x.key, rank++, x.confidence, x.evidence, x.source, x.weight, x.summary, JSON.stringify(x.key_changes || []), actor.email, now).run();
  }
  // manual 키들도 weight를 다시 쓸 필요는 없음 (사람이 정한 값 유지)

  // 티켓 메타 캐시 (LLM/regex로 잡힌 모든 키 — manual 포함)
  const allKeysForCache = new Set<string>([...ticketKeys, ...manualKeys]);
  if (jira && allKeysForCache.size) {
    for (const tk of allKeysForCache) {
      const t = await fetchTicket(jira, tk);
      if (!t) continue;
      await c.env.DB.prepare(`
        INSERT INTO jira_tickets (key, user_email, team, summary, status, assignee_email, url, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(key, user_email) DO UPDATE SET
          team=excluded.team, summary=excluded.summary, status=excluded.status,
          assignee_email=excluded.assignee_email, url=excluded.url, fetched_at=excluded.fetched_at
      `).bind(t.key, head.user_email, head.team || null, t.summary, t.status, t.assignee_email, t.url, now).run();
    }
  }

  await audit(c.env, actor, "analyze_session", head.user_email, sid, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true, ...parsed, cost_usd: cost });
});

// ── Session quality scan (no LLM; pattern-only) ─────────────────────────
// 위험 패턴(--no-verify, rm -rf, git --force 등) 카운트.
// LLM을 안 쓰므로 비용 0, 모든 세션에 자동 적용 가능.
// 추후 process/decision 품질은 별 엔드포인트에서 LLM-judge로 추가.

const QUALITY_SCANNER_VERSION = 1;

const RISK_PATTERNS: Record<string, RegExp> = {
  // Hook/signing skip flags. Match standalone flag forms.
  no_verify:      /(?:^|[\s"'`])(--no-verify|--no-gpg-sign|--no-edit)\b/g,
  // git push/reset --force (with or without --force-with-lease — both noteworthy).
  force:          /git\s+(?:push|reset)\s+[^\n;|&]*?(?:--force(?:-with-lease)?|\s-f\b)/gi,
  // git reset --hard / git checkout . / git restore --source=HEAD .
  reset_hard:     /git\s+(?:reset\s+--hard\b|checkout\s+\.\s|restore\s+(?:[^\n]*?)--source[= ]HEAD\s+\.)/gi,
  // rm -rf / rm -fr (avoid matching --force-recurse or random "rfm").
  destructive_rm: /(?:^|[\s"'`;&|])rm\s+-(?:r[fF]?|f[rR])\b/g,
  // SQL: DROP TABLE/DATABASE/SCHEMA, TRUNCATE TABLE
  drop_sql:       /\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)\b/gi,
};

function countMatches(s: string, base: RegExp): number {
  if (!s) return 0;
  // Fresh RegExp per call so /g lastIndex doesn't leak across invocations.
  const r = new RegExp(base.source, base.flags);
  let n = 0;
  while (r.exec(s)) { n++; if (n > 999) break; }
  return n;
}

function firstSnippet(s: string, base: RegExp): string | null {
  if (!s) return null;
  const r = new RegExp(base.source, base.flags);
  const m = r.exec(s);
  if (!m) return null;
  const start = Math.max(0, m.index - 30);
  const end = Math.min(s.length, m.index + m[0].length + 60);
  return s.slice(start, end).replace(/\s+/g, " ").trim();
}

type QualityResult = {
  risk_no_verify: number;
  risk_force: number;
  risk_reset_hard: number;
  risk_destructive_rm: number;
  risk_drop_sql: number;
  risk_total: number;
  message_count: number;
  bash_call_count: number;
  tool_call_count: number;
  evidence: { kind: string; seq: number; snippet: string }[];
};

function scanQualityForSession(
  rows: { seq: number; tool_calls_json: string | null }[]
): QualityResult {
  let no_verify = 0, force = 0, reset_hard = 0, destructive_rm = 0, drop_sql = 0;
  let bash_calls = 0, tool_calls = 0;
  const evidence: { kind: string; seq: number; snippet: string }[] = [];

  function addEvidenceIfRoom(kind: string, seq: number, blob: string, pat: RegExp) {
    if (evidence.length >= 10) return;
    const snip = firstSnippet(blob, pat);
    if (snip) evidence.push({ kind, seq, snippet: snip });
  }

  for (const row of rows) {
    if (!row.tool_calls_json) continue;
    let calls: any[] = [];
    try { calls = JSON.parse(row.tool_calls_json); } catch { continue; }
    if (!Array.isArray(calls)) continue;
    for (const call of calls) {
      tool_calls++;
      const input = call?.input ?? call?.params ?? {};
      const blob = typeof input === "string" ? input : JSON.stringify(input);
      if (call?.name === "Bash") bash_calls++;

      const nv = countMatches(blob, RISK_PATTERNS.no_verify);
      const fc = countMatches(blob, RISK_PATTERNS.force);
      const rh = countMatches(blob, RISK_PATTERNS.reset_hard);
      const dr = countMatches(blob, RISK_PATTERNS.destructive_rm);
      const ds = countMatches(blob, RISK_PATTERNS.drop_sql);

      if (nv) { no_verify += nv;       addEvidenceIfRoom("no_verify",      row.seq, blob, RISK_PATTERNS.no_verify); }
      if (fc) { force += fc;           addEvidenceIfRoom("force",          row.seq, blob, RISK_PATTERNS.force); }
      if (rh) { reset_hard += rh;      addEvidenceIfRoom("reset_hard",     row.seq, blob, RISK_PATTERNS.reset_hard); }
      if (dr) { destructive_rm += dr;  addEvidenceIfRoom("destructive_rm", row.seq, blob, RISK_PATTERNS.destructive_rm); }
      if (ds) { drop_sql += ds;        addEvidenceIfRoom("drop_sql",       row.seq, blob, RISK_PATTERNS.drop_sql); }
    }
  }

  return {
    risk_no_verify: no_verify,
    risk_force: force,
    risk_reset_hard: reset_hard,
    risk_destructive_rm: destructive_rm,
    risk_drop_sql: drop_sql,
    risk_total: no_verify + force + reset_hard + destructive_rm + drop_sql,
    message_count: rows.length,
    bash_call_count: bash_calls,
    tool_call_count: tool_calls,
    evidence,
  };
}

// Best-effort auto-scan triggered from /events on session_end. Optional delay
// gives the trailing /messages/bulk POST(s) time to land before we scan.
async function autoScanSession(env: Env, sid: string, delayMs = 5000) {
  if (delayMs > 0) await new Promise((r) => setTimeout(r, delayMs));
  try {
    const head: any = await env.DB.prepare(
      "SELECT MAX(user_email) user_email, MAX(team) team FROM events WHERE session_id = ?"
    ).bind(sid).first();
    if (!head?.user_email) return;
    const msgs = await env.DB.prepare(
      "SELECT seq, tool_calls_json FROM messages WHERE session_id = ? AND tool_calls_json IS NOT NULL ORDER BY seq ASC"
    ).bind(sid).all<any>();
    const result = scanQualityForSession((msgs.results || []) as any[]);
    await persistSessionQuality(env, sid, { user_email: head.user_email, team: head.team || null }, result);
  } catch {
    // best-effort; admin can re-scan via /api/admin/quality/scan-pending
  }
}

async function persistSessionQuality(
  env: Env,
  sid: string,
  meta: { user_email: string | null; team: string | null },
  result: QualityResult
) {
  await env.DB.prepare(`
    INSERT INTO session_quality (
      session_id, user_email, team, scanned_at, scanner_version,
      risk_no_verify, risk_force, risk_reset_hard, risk_destructive_rm, risk_drop_sql, risk_total,
      message_count, bash_call_count, tool_call_count, evidence_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(session_id) DO UPDATE SET
      user_email=excluded.user_email, team=excluded.team,
      scanned_at=excluded.scanned_at, scanner_version=excluded.scanner_version,
      risk_no_verify=excluded.risk_no_verify, risk_force=excluded.risk_force,
      risk_reset_hard=excluded.risk_reset_hard, risk_destructive_rm=excluded.risk_destructive_rm,
      risk_drop_sql=excluded.risk_drop_sql, risk_total=excluded.risk_total,
      message_count=excluded.message_count, bash_call_count=excluded.bash_call_count,
      tool_call_count=excluded.tool_call_count, evidence_json=excluded.evidence_json
  `).bind(
    sid, meta.user_email, meta.team, new Date().toISOString(), QUALITY_SCANNER_VERSION,
    result.risk_no_verify, result.risk_force, result.risk_reset_hard, result.risk_destructive_rm, result.risk_drop_sql, result.risk_total,
    result.message_count, result.bash_call_count, result.tool_call_count,
    JSON.stringify(result.evidence)
  ).run();
}

// Per-session: scan + persist + return result. Visible to anyone who can see the session.
app.post("/api/sessions/:id/quality-scan", async (c) => {
  const actor = c.get("actor");
  const sid = c.req.param("id");
  const head: any = await c.env.DB.prepare(
    "SELECT MAX(user_email) user_email, MAX(team) team FROM events WHERE session_id = ?"
  ).bind(sid).first();
  if (!head?.user_email) return c.json({ error: "session not found" }, 404);
  if (!canSeeUser(actor, head.user_email, head.team)) return c.json({ error: "forbidden" }, 403);

  const msgs = await c.env.DB.prepare(
    "SELECT seq, tool_calls_json FROM messages WHERE session_id = ? AND tool_calls_json IS NOT NULL ORDER BY seq ASC"
  ).bind(sid).all<any>();
  const result = scanQualityForSession((msgs.results || []) as any[]);
  await persistSessionQuality(c.env, sid, { user_email: head.user_email, team: head.team || null }, result);
  await audit(c.env, actor, "quality_scan_session", head.user_email, sid, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true, session_id: sid, scanner_version: QUALITY_SCANNER_VERSION, ...result });
});

// Read-only: pulls latest scan if present.
app.get("/api/sessions/:id/quality", async (c) => {
  const actor = c.get("actor");
  const sid = c.req.param("id");
  const row: any = await c.env.DB.prepare("SELECT * FROM session_quality WHERE session_id = ?").bind(sid).first();
  if (!row) return c.json(null);
  if (!canSeeUser(actor, row.user_email, row.team)) return c.json({ error: "forbidden" }, 403);
  let evidence: any[] = [];
  try { evidence = row.evidence_json ? JSON.parse(row.evidence_json) : []; } catch {}
  return c.json({ ...row, evidence });
});

// Admin: bulk-scan unscanned (or out-of-version) sessions in window.
app.post("/api/admin/quality/scan-pending", async (c) => {
  const actor = c.get("actor");
  if (!isAdmin(actor)) return c.json({ error: "forbidden" }, 403);
  const days  = Math.max(1, Math.min(90,  Number(c.req.query("days")  || 7)));
  const limit = Math.max(1, Math.min(200, Number(c.req.query("limit") || 100)));
  const since = new Date(Date.now() - days * 86_400_000).toISOString();

  const candidates = await c.env.DB.prepare(`
    SELECT e.session_id, MAX(e.user_email) user_email, MAX(e.team) team
    FROM events e
    LEFT JOIN session_quality q ON q.session_id = e.session_id
    WHERE e.ts >= ?
      AND e.session_id IS NOT NULL
      AND (q.session_id IS NULL OR q.scanner_version < ?)
    GROUP BY e.session_id
    ORDER BY MAX(e.ts) DESC
    LIMIT ?
  `).bind(since, QUALITY_SCANNER_VERSION, limit).all<any>();

  const sessions = (candidates.results || []) as any[];
  let scanned = 0, failed = 0, withRisk = 0;
  for (const row of sessions) {
    try {
      const msgs = await c.env.DB.prepare(
        "SELECT seq, tool_calls_json FROM messages WHERE session_id = ? AND tool_calls_json IS NOT NULL ORDER BY seq ASC"
      ).bind(row.session_id).all<any>();
      const result = scanQualityForSession((msgs.results || []) as any[]);
      await persistSessionQuality(c.env, row.session_id, { user_email: row.user_email, team: row.team || null }, result);
      scanned++;
      if (result.risk_total > 0) withRisk++;
    } catch {
      failed++;
    }
  }
  return c.json({ ok: true, scanned, failed, with_risk: withRisk, candidates: sessions.length, days, scanner_version: QUALITY_SCANNER_VERSION });
});

// Admin: aggregated risk summary (per-user roll-up + top-N risky sessions + totals).
app.get("/api/admin/quality/risk-summary", async (c) => {
  const actor = c.get("actor");
  if (!isAdmin(actor)) return c.json({ error: "forbidden" }, 403);
  const days  = Math.max(1, Math.min(90, Number(c.req.query("days") || 7)));
  const since = new Date(Date.now() - days * 86_400_000).toISOString();

  const byUser = await c.env.DB.prepare(`
    SELECT user_email, team,
           COUNT(*) AS sessions,
           SUM(CASE WHEN risk_total > 0 THEN 1 ELSE 0 END) AS risky_sessions,
           SUM(risk_no_verify)      AS no_verify,
           SUM(risk_force)          AS force_,
           SUM(risk_reset_hard)     AS reset_hard,
           SUM(risk_destructive_rm) AS destructive_rm,
           SUM(risk_drop_sql)       AS drop_sql,
           SUM(risk_total)          AS risk_total
    FROM session_quality
    WHERE scanned_at >= ?
    GROUP BY user_email, team
    ORDER BY risk_total DESC, risky_sessions DESC
    LIMIT 200
  `).bind(since).all<any>();

  const topSessions = await c.env.DB.prepare(`
    SELECT session_id, user_email, team, risk_total,
           risk_no_verify, risk_force, risk_reset_hard, risk_destructive_rm, risk_drop_sql,
           scanned_at
    FROM session_quality
    WHERE scanned_at >= ? AND risk_total > 0
    ORDER BY risk_total DESC, scanned_at DESC
    LIMIT 50
  `).bind(since).all<any>();

  const totals: any = await c.env.DB.prepare(`
    SELECT COUNT(*) AS sessions,
           SUM(CASE WHEN risk_total > 0 THEN 1 ELSE 0 END) AS risky_sessions,
           SUM(risk_total) AS risk_total
    FROM session_quality
    WHERE scanned_at >= ?
  `).bind(since).first();

  return c.json({
    days, since,
    scanner_version: QUALITY_SCANNER_VERSION,
    totals: totals || { sessions: 0, risky_sessions: 0, risk_total: 0 },
    by_user: byUser.results || [],
    top_sessions: topSessions.results || [],
  });
});

// 세션 ID만 알 때 owner email/team을 알아내기 위한 가벼운 메타 조회.
// /browse 페이지가 ?session=만으로도 deep-link되도록 클라이언트가 이걸 호출.
app.get("/api/sessions/:id/head", async (c) => {
  const actor = c.get("actor");
  const sid = c.req.param("id");
  const head: any = await c.env.DB.prepare(
    "SELECT MAX(user_email) user_email, MAX(team) team, MAX(user_name) user_name FROM events WHERE session_id = ?"
  ).bind(sid).first();
  if (!head?.user_email) return c.json({ error: "not found" }, 404);
  if (!canSeeUser(actor, head.user_email, head.team)) return c.json({ error: "forbidden" }, 403);
  return c.json({ session_id: sid, user_email: head.user_email, team: head.team || null, user_name: head.user_name || null });
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
  // session_tickets가 진실의 소스. analysis 행이 없어도 manual 링크는 있을 수 있음.
  const stRows = await c.env.DB.prepare(
    "SELECT ticket_key, rank, confidence, evidence, source, weight, summary, key_changes FROM session_tickets WHERE session_id = ? ORDER BY rank ASC, confidence DESC"
  ).bind(sid).all<any>();
  const links = (stRows.results || []) as any[];
  const keys = links.map((r: any) => r.ticket_key);
  if (!a && !keys.length) return c.json(null);
  let tickets: any[] = [];
  if (keys.length) {
    const placeholders = keys.map(() => "?").join(",");
    // user_email 매치 우선, 없으면 같은 team 매치 폴백 (team-shared cache)
    const r = await c.env.DB.prepare(
      `SELECT * FROM jira_tickets WHERE key IN (${placeholders}) AND (user_email = ? OR team = ?)`
    ).bind(...keys, head.user_email, head.team || "").all<any>();
    const byKey: Record<string, any> = {};
    for (const t of (r.results || [])) {
      // 동일 키에 user/team 모두 있으면 user 우선
      if (!byKey[t.key] || t.user_email === head.user_email) byKey[t.key] = t;
    }
    tickets = links.map((l: any) => {
      const meta = byKey[l.ticket_key] || { key: l.ticket_key };
      let kc: string[] = [];
      try { kc = l.key_changes ? JSON.parse(l.key_changes) : []; } catch {}
      return {
        ...meta,
        confidence: l.confidence, weight: l.weight, source: l.source, evidence: l.evidence, rank: l.rank,
        ticket_summary: l.summary || null,    // 티켓별 요약 (jira summary와 별개)
        ticket_key_changes: kc,
      };
    });
  }
  return c.json({
    ...(a || { session_id: sid }),
    key_changes: a?.key_changes ? JSON.parse(a.key_changes) : [],
    ticket_keys: keys,
    tickets,                            // 배열 — 새 클라이언트 (각 항목에 confidence/weight/source 포함)
    ticket: tickets[0] || null,         // 호환 — 기존 클라이언트
  });
});

// ── Ticket context (skill: /tracker-ticket context KEY) ────────────────
// 풍부한 jira 컨텍스트를 Claude 세션에 inject하기 위한 엔드포인트.
app.get("/api/tickets/:key/context", async (c) => {
  const actor = c.get("actor");
  const key = c.req.param("key").toUpperCase();
  // 사용자의 jira 토큰 우선; 없으면 같은 팀의 다른 사용자 jira 토큰 폴백
  let conn = await getJiraConn(c.env, actor.email);
  if (!conn && actor.team) {
    const peers = await c.env.DB.prepare(
      "SELECT user_email FROM tokens WHERE team = ? AND user_email <> ? AND revoked_at IS NULL LIMIT 5"
    ).bind(actor.team, actor.email).all<any>();
    for (const p of (peers.results || [])) {
      conn = await getJiraConn(c.env, p.user_email);
      if (conn) break;
    }
  }
  if (!conn) return c.json({ error: "no jira integration available" }, 503);
  const ctx = await fetchTicketContext(conn, key, { maxComments: 8 });
  if (!ctx) return c.json({ error: "ticket not found" }, 404);
  // Confluence 관련 페이지(직접 link + 키워드 검색) — opt-out 가능: ?confluence=0
  const wantConf = c.req.query("confluence") !== "0";
  let confluence: any[] = [];
  if (wantConf) {
    try { confluence = await fetchConfluenceForTicket(conn, key, ctx.summary || "", { maxLinked: 5, maxSearched: 3 }); } catch {}
  }
  return c.json({ ...ctx, confluence });
});

// ── Confluence 시드 (테스트용, admin만) ─────────────────────────────────
// POST /api/admin/test/seed-confluence  body: { ticket_key, space_key? }
// 1) 사용 가능한 space 조회 (없으면 자동 선택)
// 2) 테스트 페이지 생성 (티켓 정보를 문서화한 form)
// 3) 해당 티켓에 Confluence 페이지를 remote link로 추가
app.post("/api/admin/test/seed-confluence", async (c) => {
  const actor = c.get("actor");
  if (!isAdmin(actor)) return c.json({ error: "forbidden (admin only)" }, 403);
  const body = await c.req.json<any>().catch(() => ({}));
  const ticketKey = String(body.ticket_key || "").trim().toUpperCase();
  if (!/^[A-Z][A-Z0-9]{1,9}-\d+$/.test(ticketKey)) return c.json({ error: "invalid ticket_key" }, 400);
  const conn = await getJiraConn(c.env, actor.email);
  if (!conn) return c.json({ error: "no jira integration on actor" }, 503);
  // 티켓 존재 확인
  const ticket = await fetchTicket(conn, ticketKey);
  if (!ticket) return c.json({ error: "ticket not found" }, 404);
  // space 결정: 명시 → personal → 첫 visible
  let spaceKey = body.space_key as string | undefined;
  if (!spaceKey) spaceKey = await getPersonalSpaceKey(conn) || undefined;
  let availableSpaces: any[] = [];
  if (!spaceKey) {
    availableSpaces = await listConfluenceSpaces(conn, 20);
    if (!availableSpaces.length) return c.json({ error: "no Confluence spaces visible — provide space_key" }, 503);
    spaceKey = availableSpaces[0].key;
  }
  // 페이지 본문 (storage XHTML) — 일반적인 작업 노트 형식
  const now = new Date().toISOString();
  const html = `
    <h1>${escapeXml(ticket.summary || ticketKey)}</h1>
    <p><em>${escapeXml(ticketKey)} 작업 노트 · ${now.slice(0,10)} 작성</em></p>
    <h2>개요</h2>
    <p>${escapeXml(ticket.summary || "(요약 없음)")} 관련 작업의 배경, 범위, 일정을 정리합니다.</p>
    <h2>관련 티켓</h2>
    <ul><li><a href="${ticket.url}">${ticketKey}</a> — ${escapeXml(ticket.summary || "")} (${escapeXml(ticket.status || "-")})</li></ul>
    <h2>배경</h2>
    <p>본 작업은 ${escapeXml(ticket.summary || ticketKey)}의 요구사항을 정리하고 우선순위를 결정하기 위한 사전 검토 단계입니다. 이해관계자 의견과 도메인 제약을 반영하여 다음 섹션의 범위를 확정합니다.</p>
    <h2>범위 (Scope)</h2>
    <ul>
      <li>요구사항 수집 및 정의</li>
      <li>기술 검토 및 위험 식별</li>
      <li>일정 산정 및 마일스톤 설정</li>
      <li>완료 조건(DoD) 합의</li>
    </ul>
    <h2>고려 사항</h2>
    <ul>
      <li>의존 시스템 및 데이터 흐름</li>
      <li>성능 / 보안 / 운영 영향도</li>
      <li>롤백 및 점진적 출시 전략</li>
    </ul>
    <h2>마일스톤</h2>
    <table><tbody>
      <tr><th>단계</th><th>산출물</th><th>예상 기간</th></tr>
      <tr><td>설계</td><td>설계 문서, 데이터 모델</td><td>1주</td></tr>
      <tr><td>구현</td><td>핵심 기능 + 단위 테스트</td><td>2주</td></tr>
      <tr><td>검증</td><td>통합 테스트 + 리뷰</td><td>1주</td></tr>
    </tbody></table>
    <h2>이력</h2>
    <table><tbody>
      <tr><th>일자</th><th>변경</th><th>담당</th></tr>
      <tr><td>${now.slice(0,10)}</td><td>최초 작성</td><td>${escapeXml(actor.name || actor.email)}</td></tr>
    </tbody></table>
  `.trim();
  const pageTitle = `${ticketKey} 작업 노트 — ${(ticket.summary || "").slice(0, 60)}`;
  const page = await createConfluencePage(conn, spaceKey!, pageTitle, html);
  if (!page.ok) return c.json({ error: "page create failed: " + page.error, tried_space: spaceKey, available_spaces: availableSpaces.map(s => s.key) }, 500);
  // remote link 추가
  const link = await addJiraRemoteLink(conn, ticketKey, page.url!, pageTitle);
  await audit(c.env, actor, "confluence_seed", actor.email, ticketKey, c.req.header("cf-connecting-ip") || null);
  return c.json({
    ok: true,
    ticket_key: ticketKey,
    space_key: spaceKey,
    page_id: page.id,
    page_url: page.url,
    jira_link_ok: link.ok,
    jira_link_error: link.error || null,
    note: "이제 GET /api/tickets/" + ticketKey + "/context 호출 시 confluence[] 에 이 페이지가 포함됩니다.",
  });
});

function escapeXml(s: string): string {
  return String(s || "").replace(/[<>&"']/g, c => ({"<":"&lt;",">":"&gt;","&":"&amp;","\"":"&quot;","'":"&apos;"}[c] as string));
}

// 시드 정리: Confluence 페이지 삭제 + Jira remote link 제거 (admin only)
app.post("/api/admin/test/teardown-confluence", async (c) => {
  const actor = c.get("actor");
  if (!isAdmin(actor)) return c.json({ error: "forbidden" }, 403);
  const body = await c.req.json<any>().catch(() => ({}));
  const pageId = String(body.page_id || "").trim();
  const ticketKey = String(body.ticket_key || "").trim().toUpperCase();
  if (!pageId) return c.json({ error: "page_id required" }, 400);
  const conn = await getJiraConn(c.env, actor.email);
  if (!conn) return c.json({ error: "no jira integration on actor" }, 503);
  const pageUrl = `${conn.base_url.replace(/\/$/, "")}/wiki/spaces/.+/pages/${pageId}`;
  // Jira remote link 제거 (티켓 키 제공 시)
  let linkRemoved = 0, linkErr: string | null = null;
  if (ticketKey) {
    const r = await removeJiraRemoteLinkByUrl(conn, ticketKey, `/pages/${pageId}`);
    linkRemoved = r.removed; linkErr = r.error || null;
  }
  // Confluence 페이지 삭제
  const del = await deleteConfluencePage(conn, pageId);
  await audit(c.env, actor, "confluence_teardown", actor.email, ticketKey || pageId, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: del.ok, page_deleted: del.ok, page_error: del.error || null, jira_link_removed: linkRemoved, jira_link_error: linkErr });
});

// ── Session-ticket segments (시간축 위 명시적 경계) ──────────────────────
async function recomputeWeightsFromSegments(env: Env, sid: string) {
  // segments 기반 duration 합 → session_tickets.weight 자동 갱신.
  const segs = await env.DB.prepare(
    "SELECT ticket_key, started_at, COALESCE(ended_at, datetime('now')) ended_at FROM session_ticket_segments WHERE session_id = ?"
  ).bind(sid).all<any>();
  const dur: Record<string, number> = {};
  let total = 0;
  for (const s of (segs.results || []) as any[]) {
    const d = (new Date(s.ended_at).getTime() - new Date(s.started_at).getTime()) / 1000;
    if (d <= 0) continue;
    dur[s.ticket_key] = (dur[s.ticket_key] || 0) + d;
    total += d;
  }
  if (total <= 0) return;
  for (const [key, sec] of Object.entries(dur)) {
    const w = sec / total;
    // session_tickets에 없으면 추가 (segment-only 키)
    await env.DB.prepare(`
      INSERT INTO session_tickets (session_id, ticket_key, rank, confidence, evidence, source, weight, created_by, created_at)
      VALUES (?, ?, 0, 1.0, 'segment', 'manual', ?, 'segment', datetime('now'))
      ON CONFLICT(session_id, ticket_key) DO UPDATE SET weight = ?
    `).bind(sid, key, w, w).run();
  }
}

app.post("/api/sessions/:id/segments/start", async (c) => {
  const actor = c.get("actor");
  const sid = c.req.param("id");
  const body = await c.req.json<any>().catch(() => ({}));
  const key = String(body.ticket_key || "").trim().toUpperCase();
  if (!/^[A-Z][A-Z0-9]{1,9}-\d+$/.test(key)) return c.json({ error: "invalid ticket key" }, 400);
  const head: any = await c.env.DB.prepare(
    "SELECT MAX(user_email) user_email, MAX(team) team FROM events WHERE session_id = ?"
  ).bind(sid).first();
  // 세션이 events에 없으면 actor를 신뢰 (세션이 막 시작된 경우 hooks가 events 채우기 전)
  const owner = head?.user_email || actor.email;
  const team = head?.team || actor.team;
  if (!canSeeUser(actor, owner, team)) return c.json({ error: "forbidden" }, 403);
  const now = new Date().toISOString();
  // 이전 open segment 자동 close
  await c.env.DB.prepare(
    "UPDATE session_ticket_segments SET ended_at = ?, user_action = 'switch' WHERE session_id = ? AND ended_at IS NULL"
  ).bind(now, sid).run();
  // 새 segment 시작
  const r = await c.env.DB.prepare(`
    INSERT INTO session_ticket_segments (session_id, ticket_key, started_at, user_action, created_by)
    VALUES (?, ?, ?, 'start', ?)
  `).bind(sid, key, now, actor.email).run();
  // 매칭에 manual 링크도 보장 (분석 후 보존됨)
  await c.env.DB.prepare(`
    INSERT INTO session_tickets (session_id, ticket_key, rank, confidence, evidence, source, weight, created_by, created_at)
    VALUES (?, ?, 0, 1.0, 'segment-start', 'manual', 0, ?, ?)
    ON CONFLICT(session_id, ticket_key) DO UPDATE SET source='manual', evidence='segment-start'
  `).bind(sid, key, actor.email, now).run();
  // ── Auto-group: 같은 (user, repo)로 묶이는 모든 세션이 한 그룹에 자동 합류 ──
  // 사용자는 /tracker-ticket start KEY 한 번만 하면 되고, 워커/하위 세션은 자동.
  let groupInfo: any = null;
  try {
    const repoInfo: any = await c.env.DB.prepare(
      "SELECT remote_url, repo_root FROM session_git WHERE session_id = ?"
    ).bind(sid).first();
    const repoRemote = repoInfo?.remote_url || null;
    const repoRoot = repoInfo?.repo_root || null;
    // 이 세션이 이미 어느 그룹에 속해 있는지 확인 (수동 attach 등)
    const existing: any = await c.env.DB.prepare(
      "SELECT group_id FROM session_group_members WHERE session_id = ? LIMIT 1"
    ).bind(sid).first();
    let group: any = null;
    if (existing?.group_id) {
      group = await c.env.DB.prepare("SELECT * FROM session_groups WHERE id = ?")
        .bind(existing.group_id).first<any>();
    }
    if (!group) {
      group = await findOpenGroupByRepo(c.env, owner, repoRemote, repoRoot);
    }
    if (!group && (repoRemote || repoRoot)) {
      // 새 그룹: orchestrator로 이 세션 등록
      const gid = genGroupId();
      const repoLabel = repoRemote
        ? repoRemote.replace(/^.*[/:]/, "").replace(/\.git$/, "")
        : (repoRoot || "").split("/").slice(-1)[0];
      const groupName = `${key} · ${repoLabel || "auto"}`;
      const nowStr = new Date().toISOString();
      await c.env.DB.prepare(`
        INSERT INTO session_groups
          (id, name, owner_email, team, repo_remote, repo_root, active_ticket_key, created_at, last_activity_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(gid, groupName, owner, team || null, repoRemote, repoRoot, key, nowStr, nowStr).run();
      group = { id: gid, name: groupName, active_ticket_key: key };
      await ensureMember(c.env, gid, sid, "orchestrator");
    } else if (group) {
      // 기존 그룹 재사용: 멤버십 보장 + active ticket 갱신 + 모든 멤버에게 segment 전파
      await ensureMember(c.env, group.id, sid, group.active_ticket_key === null ? "orchestrator" : "worker");
      await c.env.DB.prepare(
        "UPDATE session_groups SET active_ticket_key = ?, last_activity_at = ? WHERE id = ?"
      ).bind(key, new Date().toISOString(), group.id).run();
      // 그룹 내 다른 멤버들에게도 segment 전파
      const others = await c.env.DB.prepare(
        "SELECT session_id FROM session_group_members WHERE group_id = ? AND session_id != ?"
      ).bind(group.id, sid).all<any>();
      for (const m of (others.results || []) as any[]) {
        await openSegmentForSession(c.env, m.session_id, key, actor.email, "group-propagate");
      }
      group.active_ticket_key = key;
    }
    if (group) groupInfo = { id: group.id, name: group.name, active_ticket_key: group.active_ticket_key };
  } catch { /* group propagation is best-effort */ }

  // 티켓 컨텍스트도 함께 응답 (skill에서 바로 inject 가능)
  let context: any = null;
  const conn = await getJiraConn(c.env, owner);
  if (conn) context = await fetchTicketContext(conn, key, { maxComments: 5 });
  await audit(c.env, actor, "segment_start", owner, sid, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true, segment_id: (r as any).meta?.last_row_id, ticket_key: key, started_at: now, context, group: groupInfo });
});

app.post("/api/sessions/:id/segments/end", async (c) => {
  const actor = c.get("actor");
  const sid = c.req.param("id");
  const head: any = await c.env.DB.prepare(
    "SELECT MAX(user_email) user_email, MAX(team) team FROM events WHERE session_id = ?"
  ).bind(sid).first();
  const owner = head?.user_email || actor.email;
  if (!canSeeUser(actor, owner, head?.team)) return c.json({ error: "forbidden" }, 403);
  const now = new Date().toISOString();
  const r = await c.env.DB.prepare(
    "UPDATE session_ticket_segments SET ended_at = ?, user_action = 'end' WHERE session_id = ? AND ended_at IS NULL"
  ).bind(now, sid).run();
  await recomputeWeightsFromSegments(c.env, sid);
  return c.json({ ok: true, closed: (r as any).meta?.changes || 0, ended_at: now });
});

app.get("/api/sessions/:id/segments", async (c) => {
  const actor = c.get("actor");
  const sid = c.req.param("id");
  const head: any = await c.env.DB.prepare(
    "SELECT MAX(user_email) user_email, MAX(team) team FROM events WHERE session_id = ?"
  ).bind(sid).first();
  if (head?.user_email && !canSeeUser(actor, head.user_email, head.team)) return c.json({ error: "forbidden" }, 403);
  const r = await c.env.DB.prepare(
    "SELECT id, ticket_key, started_at, ended_at, user_action, jira_comment_id FROM session_ticket_segments WHERE session_id = ? ORDER BY started_at ASC"
  ).bind(sid).all<any>();
  return c.json(r.results || []);
});

// ── Optimize / Compare: waste-pattern detection + per-model metrics ──
// Port of getagentseal/codeburn server-side rules. Reads events + messages
// directly, no client-side filesystem scan (Phase 1).
app.get("/api/users/:email/optimize", async (c) => {
  const actor = c.get("actor");
  const email = decodeURIComponent(c.req.param("email"));
  if (!canSeeUser(actor, email, null)) return c.json({ error: "forbidden" }, 403);
  const days = Math.min(90, Math.max(1, parseInt(c.req.query("days") || "30", 10)));
  const report = await runOptimize(c.env, email, days);
  await audit(c.env, actor, "optimize", email, null, c.req.header("cf-connecting-ip") || null);
  return c.json(report);
});

app.get("/api/users/:email/compare", async (c) => {
  const actor = c.get("actor");
  const email = decodeURIComponent(c.req.param("email"));
  if (!canSeeUser(actor, email, null)) return c.json({ error: "forbidden" }, 403);
  const days = Math.min(90, Math.max(1, parseInt(c.req.query("days") || "30", 10)));
  const stats = await aggregateModelStats(c.env, email, days);
  const modelA = c.req.query("modelA");
  const modelB = c.req.query("modelB");
  let comparison: any = null;
  if (modelA && modelB) {
    const a = stats.find(s => s.model === modelA || s.model.includes(modelA));
    const b = stats.find(s => s.model === modelB || s.model.includes(modelB));
    if (a && b) comparison = { a, b, rows: compareModels(a, b) };
  }
  return c.json({ days, user_email: email, models: stats, comparison });
});

// ── Groups: bundle multiple sessions (e.g. agent-team workers) into one task ──
function genGroupId() {
  return "g_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16);
}

// Find an open group matching (user, repo). Repo identity prefers remote_url
// (stable across worktrees) and falls back to repo_root for repos w/o remote.
// TTL: groups inactive for >7d are ignored — a fresh ticket starts a new group.
async function findOpenGroupByRepo(
  env: Env,
  ownerEmail: string,
  repoRemote: string | null,
  repoRoot: string | null,
): Promise<any | null> {
  if (!repoRemote && !repoRoot) return null;
  const ttl = new Date(Date.now() - 7 * 86400_000).toISOString();
  return await env.DB.prepare(`
    SELECT * FROM session_groups
    WHERE owner_email = ?
      AND closed_at IS NULL
      AND COALESCE(last_activity_at, created_at) > ?
      AND ((? IS NOT NULL AND repo_remote = ?) OR (? IS NOT NULL AND repo_root = ?))
    ORDER BY COALESCE(last_activity_at, created_at) DESC
    LIMIT 1
  `).bind(ownerEmail, ttl, repoRemote, repoRemote, repoRoot, repoRoot).first<any>();
}

// Attach a session to a group (idempotent).
async function ensureMember(env: Env, gid: string, sid: string, role: string) {
  const now = new Date().toISOString();
  await env.DB.prepare(
    "INSERT OR IGNORE INTO session_group_members (group_id, session_id, role, joined_at) VALUES (?, ?, ?, ?)"
  ).bind(gid, sid, role, now).run();
  await env.DB.prepare(
    "UPDATE session_groups SET last_activity_at = ? WHERE id = ?"
  ).bind(now, gid).run();
}

// Open a fresh ticket segment for the given session (closing any prior open one).
async function openSegmentForSession(
  env: Env,
  sid: string,
  ticketKey: string,
  createdBy: string,
  evidence: string = "auto-group",
) {
  const now = new Date().toISOString();
  await env.DB.prepare(
    "UPDATE session_ticket_segments SET ended_at = ?, user_action = 'switch' WHERE session_id = ? AND ended_at IS NULL"
  ).bind(now, sid).run();
  await env.DB.prepare(
    "INSERT INTO session_ticket_segments (session_id, ticket_key, started_at, user_action, created_by) VALUES (?, ?, ?, 'start', ?)"
  ).bind(sid, ticketKey, now, createdBy).run();
  await env.DB.prepare(`
    INSERT INTO session_tickets (session_id, ticket_key, rank, confidence, evidence, source, weight, created_by, created_at)
    VALUES (?, ?, 0, 1.0, ?, 'manual', 0, ?, ?)
    ON CONFLICT(session_id, ticket_key) DO UPDATE SET source='manual', evidence=excluded.evidence
  `).bind(sid, ticketKey, evidence, createdBy, now).run();
}

// Create a group, optionally auto-attach the caller's session as orchestrator.
app.post("/api/groups", async (c) => {
  const actor = c.get("actor");
  const body = await c.req.json<any>().catch(() => ({}));
  const id = genGroupId();
  const name = body.name ? String(body.name).slice(0, 200) : null;
  const sid = body.session_id ? String(body.session_id).trim() : null;
  const role = body.role ? String(body.role).slice(0, 32) : (sid ? "orchestrator" : null);
  const now = new Date().toISOString();
  await c.env.DB.prepare(
    "INSERT INTO session_groups (id, name, owner_email, team, created_at) VALUES (?, ?, ?, ?, ?)"
  ).bind(id, name, actor.email, actor.team || null, now).run();
  if (sid) {
    await c.env.DB.prepare(
      "INSERT OR IGNORE INTO session_group_members (group_id, session_id, role, joined_at) VALUES (?, ?, ?, ?)"
    ).bind(id, sid, role, now).run();
  }
  await audit(c.env, actor, "group_create", actor.email, sid, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true, group_id: id, name, role, owner_email: actor.email });
});

// Attach a session to an existing group.
app.post("/api/groups/:gid/attach", async (c) => {
  const actor = c.get("actor");
  const gid = c.req.param("gid");
  const body = await c.req.json<any>().catch(() => ({}));
  const sid = String(body.session_id || "").trim();
  const role = body.role ? String(body.role).slice(0, 32) : "worker";
  if (!sid) return c.json({ error: "session_id required" }, 400);
  const grp: any = await c.env.DB.prepare(
    "SELECT owner_email, team, closed_at FROM session_groups WHERE id = ?"
  ).bind(gid).first();
  if (!grp) return c.json({ error: "group not found" }, 404);
  if (grp.closed_at) return c.json({ error: "group closed" }, 400);
  if (!canSeeUser(actor, grp.owner_email, grp.team)) return c.json({ error: "forbidden" }, 403);
  const now = new Date().toISOString();
  await c.env.DB.prepare(
    "INSERT OR IGNORE INTO session_group_members (group_id, session_id, role, joined_at) VALUES (?, ?, ?, ?)"
  ).bind(gid, sid, role, now).run();
  await audit(c.env, actor, "group_attach", grp.owner_email, sid, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true, group_id: gid, session_id: sid, role });
});

// List groups visible to the caller (own + admin sees all).
app.get("/api/groups", async (c) => {
  const actor = c.get("actor");
  const limit = Math.min(200, parseInt(c.req.query("limit") || "50", 10));
  const stmt = isAdmin(actor)
    ? c.env.DB.prepare("SELECT * FROM session_groups ORDER BY created_at DESC LIMIT ?").bind(limit)
    : c.env.DB.prepare("SELECT * FROM session_groups WHERE owner_email = ? ORDER BY created_at DESC LIMIT ?").bind(actor.email, limit);
  const r = await stmt.all<any>();
  // attach member counts
  const out: any[] = [];
  for (const g of (r.results || []) as any[]) {
    const cnt: any = await c.env.DB.prepare(
      "SELECT COUNT(*) AS n FROM session_group_members WHERE group_id = ?"
    ).bind(g.id).first();
    out.push({ ...g, member_count: cnt?.n || 0 });
  }
  return c.json(out);
});

// Group detail: members + tickets-rollup.
app.get("/api/groups/:gid", async (c) => {
  const actor = c.get("actor");
  const gid = c.req.param("gid");
  const grp: any = await c.env.DB.prepare("SELECT * FROM session_groups WHERE id = ?").bind(gid).first();
  if (!grp) return c.json({ error: "group not found" }, 404);
  if (!canSeeUser(actor, grp.owner_email, grp.team)) return c.json({ error: "forbidden" }, 403);
  const members = await c.env.DB.prepare(`
    SELECT m.session_id, m.role, m.joined_at,
           (SELECT MAX(cwd) FROM events WHERE session_id = m.session_id) AS cwd,
           (SELECT MAX(model) FROM events WHERE session_id = m.session_id) AS model,
           (SELECT MIN(ts) FROM events WHERE session_id = m.session_id) AS started,
           (SELECT MAX(ts) FROM events WHERE session_id = m.session_id) AS last_event,
           (SELECT COUNT(*) FROM events WHERE session_id = m.session_id) AS events,
           (SELECT COALESCE(SUM(input_tokens),0) + COALESCE(SUM(output_tokens),0) +
                   COALESCE(SUM(cache_read_tokens),0) + COALESCE(SUM(cache_create_tokens),0)
            FROM events WHERE session_id = m.session_id) AS tokens,
           (SELECT text FROM messages WHERE session_id = m.session_id AND role = 'user' AND text IS NOT NULL ORDER BY seq ASC LIMIT 1) AS first_user_msg
    FROM session_group_members m WHERE m.group_id = ? ORDER BY m.joined_at ASC
  `).bind(gid).all<any>();
  const tickets = await c.env.DB.prepare(`
    SELECT s.ticket_key,
           COUNT(DISTINCT s.session_id) AS sessions,
           COUNT(*) AS segments,
           SUM((julianday(COALESCE(s.ended_at, datetime('now'))) - julianday(s.started_at)) * 86400) AS sec,
           MIN(s.started_at) AS first_started,
           MAX(COALESCE(s.ended_at, datetime('now'))) AS last_ended
    FROM session_ticket_segments s
    WHERE s.session_id IN (SELECT session_id FROM session_group_members WHERE group_id = ?)
    GROUP BY s.ticket_key ORDER BY sec DESC
  `).bind(gid).all<any>();
  const comments = await c.env.DB.prepare(
    "SELECT ticket_key, jira_comment_id, posted_at FROM group_ticket_comments WHERE group_id = ?"
  ).bind(gid).all<any>();
  return c.json({
    ...grp,
    members: members.results || [],
    tickets: tickets.results || [],
    writeback_comments: comments.results || [],
  });
});

// Start a ticket segment for ALL member sessions at once.
app.post("/api/groups/:gid/segments/start", async (c) => {
  const actor = c.get("actor");
  const gid = c.req.param("gid");
  const body = await c.req.json<any>().catch(() => ({}));
  const key = String(body.ticket_key || "").trim().toUpperCase();
  if (!/^[A-Z][A-Z0-9]{1,9}-\d+$/.test(key)) return c.json({ error: "invalid ticket key" }, 400);
  const grp: any = await c.env.DB.prepare(
    "SELECT owner_email, team, closed_at FROM session_groups WHERE id = ?"
  ).bind(gid).first();
  if (!grp) return c.json({ error: "group not found" }, 404);
  if (grp.closed_at) return c.json({ error: "group closed" }, 400);
  if (!canSeeUser(actor, grp.owner_email, grp.team)) return c.json({ error: "forbidden" }, 403);
  const members = await c.env.DB.prepare(
    "SELECT session_id FROM session_group_members WHERE group_id = ?"
  ).bind(gid).all<any>();
  const sids: string[] = (members.results || []).map((m: any) => m.session_id);
  const now = new Date().toISOString();
  for (const sid of sids) {
    await c.env.DB.prepare(
      "UPDATE session_ticket_segments SET ended_at = ?, user_action = 'switch' WHERE session_id = ? AND ended_at IS NULL"
    ).bind(now, sid).run();
    await c.env.DB.prepare(
      "INSERT INTO session_ticket_segments (session_id, ticket_key, started_at, user_action, created_by) VALUES (?, ?, ?, 'start', ?)"
    ).bind(sid, key, now, actor.email).run();
    await c.env.DB.prepare(`
      INSERT INTO session_tickets (session_id, ticket_key, rank, confidence, evidence, source, weight, created_by, created_at)
      VALUES (?, ?, 0, 1.0, 'group-segment-start', 'manual', 0, ?, ?)
      ON CONFLICT(session_id, ticket_key) DO UPDATE SET source='manual', evidence='group-segment-start'
    `).bind(sid, key, actor.email, now).run();
  }
  let context: any = null;
  const conn = await getJiraConn(c.env, grp.owner_email);
  if (conn) context = await fetchTicketContext(conn, key, { maxComments: 5 });
  await audit(c.env, actor, "group_segment_start", grp.owner_email, gid, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true, group_id: gid, ticket_key: key, sessions: sids.length, started_at: now, context });
});

// End any open segment in all member sessions.
app.post("/api/groups/:gid/segments/end", async (c) => {
  const actor = c.get("actor");
  const gid = c.req.param("gid");
  const grp: any = await c.env.DB.prepare(
    "SELECT owner_email, team FROM session_groups WHERE id = ?"
  ).bind(gid).first();
  if (!grp) return c.json({ error: "group not found" }, 404);
  if (!canSeeUser(actor, grp.owner_email, grp.team)) return c.json({ error: "forbidden" }, 403);
  const now = new Date().toISOString();
  const r = await c.env.DB.prepare(
    "UPDATE session_ticket_segments SET ended_at = ?, user_action = 'end' WHERE ended_at IS NULL AND session_id IN (SELECT session_id FROM session_group_members WHERE group_id = ?)"
  ).bind(now, gid).run();
  const members = await c.env.DB.prepare(
    "SELECT session_id FROM session_group_members WHERE group_id = ?"
  ).bind(gid).all<any>();
  for (const m of (members.results || []) as any[]) await recomputeWeightsFromSegments(c.env, m.session_id);
  return c.json({ ok: true, closed: (r as any).meta?.changes || 0, ended_at: now });
});

// Aggregated writeback: one Jira comment per ticket combining all member sessions.
app.post("/api/groups/:gid/writeback", async (c) => {
  const actor = c.get("actor");
  const gid = c.req.param("gid");
  const grp: any = await c.env.DB.prepare("SELECT * FROM session_groups WHERE id = ?").bind(gid).first();
  if (!grp) return c.json({ error: "group not found" }, 404);
  if (!canSeeUser(actor, grp.owner_email, grp.team)) return c.json({ error: "forbidden" }, 403);
  const now = new Date().toISOString();
  await c.env.DB.prepare(
    "UPDATE session_ticket_segments SET ended_at = ?, user_action = COALESCE(user_action, 'end') WHERE ended_at IS NULL AND session_id IN (SELECT session_id FROM session_group_members WHERE group_id = ?)"
  ).bind(now, gid).run();
  const members = await c.env.DB.prepare(
    "SELECT session_id, role FROM session_group_members WHERE group_id = ?"
  ).bind(gid).all<any>();
  const sids: string[] = (members.results || []).map((m: any) => m.session_id);
  for (const sid of sids) await recomputeWeightsFromSegments(c.env, sid);
  // Per-ticket / per-session aggregation.
  const segs = await c.env.DB.prepare(`
    SELECT ticket_key, session_id,
           SUM((julianday(COALESCE(ended_at, datetime('now'))) - julianday(started_at)) * 86400) AS sec,
           MIN(started_at) AS first_started,
           MAX(COALESCE(ended_at, datetime('now'))) AS last_ended,
           COUNT(*) AS n
    FROM session_ticket_segments
    WHERE session_id IN (SELECT session_id FROM session_group_members WHERE group_id = ?)
    GROUP BY ticket_key, session_id
    ORDER BY ticket_key, first_started
  `).bind(gid).all<any>();
  const byTicket: Record<string, any[]> = {};
  for (const r of (segs.results || []) as any[]) {
    (byTicket[r.ticket_key] = byTicket[r.ticket_key] || []).push(r);
  }
  // Per-session ticket summaries (key_changes etc.)
  const stRows = await c.env.DB.prepare(`
    SELECT session_id, ticket_key, summary, key_changes
    FROM session_tickets
    WHERE session_id IN (SELECT session_id FROM session_group_members WHERE group_id = ?)
  `).bind(gid).all<any>();
  const stMap: Record<string, Record<string, any>> = {};
  for (const r of (stRows.results || []) as any[]) {
    (stMap[r.ticket_key] = stMap[r.ticket_key] || {})[r.session_id] = r;
  }
  const conn = await getJiraConn(c.env, grp.owner_email);
  const results: any[] = [];
  for (const [ticket_key, perSession] of Object.entries(byTicket)) {
    if (!conn) { results.push({ ticket_key, ok: false, error: "no jira" }); continue; }
    const totalSec = perSession.reduce((s, r) => s + Math.max(0, Math.round(r.sec || 0)), 0);
    const th = Math.floor(totalSec / 3600), tm = Math.floor((totalSec % 3600) / 60);
    const totalDur = th ? `${th}h ${tm}m` : `${tm}m`;
    const lines: string[] = [];
    lines.push(`🤖 Claude Code 그룹 작업 기록 (${perSession.length}개 세션)`);
    if (grp.name) lines.push(`그룹: ${grp.name}`);
    lines.push(`총 시간: ${totalDur}`);
    lines.push("");
    for (const ps of perSession) {
      const sec = Math.max(0, Math.round(ps.sec || 0));
      const sh = Math.floor(sec / 3600), sm = Math.floor((sec % 3600) / 60);
      const dur = sh ? `${sh}h ${sm}m` : `${sm}m`;
      const st = stMap[ticket_key]?.[ps.session_id];
      lines.push(`▸ session ${String(ps.session_id).slice(0, 8)}…  ${dur}  (${ps.n} 세그먼트)`);
      if (st?.summary) lines.push(`  ${st.summary}`);
      try {
        const kc = st?.key_changes ? JSON.parse(st.key_changes) : [];
        if (kc.length) lines.push("  - " + kc.slice(0, 3).join("\n  - "));
      } catch {}
    }
    lines.push("");
    lines.push(`그룹 보기: ${new URL(c.req.url).origin}/g/${gid}`);
    const r = await addComment(conn, ticket_key, lines.join("\n"));
    if (r.ok && r.id) {
      await c.env.DB.prepare(`
        INSERT INTO group_ticket_comments (group_id, ticket_key, jira_comment_id, posted_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(group_id, ticket_key) DO UPDATE SET
          jira_comment_id = excluded.jira_comment_id,
          posted_at = excluded.posted_at
      `).bind(gid, ticket_key, r.id, new Date().toISOString()).run();
    }
    results.push({ ticket_key, ok: r.ok, error: r.error, comment_id: r.id, total_duration: totalDur, sessions: perSession.length });
  }
  await audit(c.env, actor, "group_writeback", grp.owner_email, gid, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true, group_id: gid, results });
});

// Close a group (no further attaches).
app.post("/api/groups/:gid/close", async (c) => {
  const actor = c.get("actor");
  const gid = c.req.param("gid");
  const grp: any = await c.env.DB.prepare(
    "SELECT owner_email, team FROM session_groups WHERE id = ?"
  ).bind(gid).first();
  if (!grp) return c.json({ error: "group not found" }, 404);
  if (!canSeeUser(actor, grp.owner_email, grp.team)) return c.json({ error: "forbidden" }, 403);
  await c.env.DB.prepare(
    "UPDATE session_groups SET closed_at = ? WHERE id = ?"
  ).bind(new Date().toISOString(), gid).run();
  return c.json({ ok: true });
});

// 세션 종료 시 (또는 /tracker-ticket done) — 각 segment에 대해 jira 코멘트 등록 + 옵션으로 상태 전이
app.post("/api/sessions/:id/writeback", async (c) => {
  const actor = c.get("actor");
  const sid = c.req.param("id");
  const head: any = await c.env.DB.prepare(
    "SELECT MAX(user_email) user_email, MAX(team) team FROM events WHERE session_id = ?"
  ).bind(sid).first();
  if (!head?.user_email) return c.json({ error: "session not found" }, 404);
  if (!canSeeUser(actor, head.user_email, head.team)) return c.json({ error: "forbidden" }, 403);

  // ── If this session is in a group, redirect to group writeback so the work
  //    of all member sessions lands in one combined Jira comment per ticket. ──
  const grpRow: any = await c.env.DB.prepare(
    "SELECT group_id FROM session_group_members WHERE session_id = ? LIMIT 1"
  ).bind(sid).first();
  if (grpRow?.group_id) {
    const gurl = new URL(c.req.url);
    gurl.pathname = `/api/groups/${encodeURIComponent(grpRow.group_id)}/writeback`;
    const gres = await fetch(gurl.toString(), {
      method: "POST",
      headers: { Authorization: c.req.header("authorization") || "", "Content-Type": "application/json" },
      body: "{}",
    });
    const gj: any = await gres.json().catch(() => ({}));
    return c.json({ ok: gj.ok, sid, group_id: grpRow.group_id, results: gj.results || [], routed_to_group: true });
  }

  // open segment 강제 종료
  const now = new Date().toISOString();
  await c.env.DB.prepare(
    "UPDATE session_ticket_segments SET ended_at = ?, user_action = COALESCE(user_action, 'end') WHERE session_id = ? AND ended_at IS NULL"
  ).bind(now, sid).run();
  await recomputeWeightsFromSegments(c.env, sid);
  // 분석 (요약 가져오기)
  const a: any = await c.env.DB.prepare("SELECT summary FROM session_analysis WHERE session_id = ?").bind(sid).first();
  const sessionSummary = a?.summary || "Claude Code 세션 작업";
  const stRows = await c.env.DB.prepare(
    "SELECT ticket_key, summary, key_changes FROM session_tickets WHERE session_id = ?"
  ).bind(sid).all<any>();
  const ticketDetail: Record<string, any> = {};
  for (const r of (stRows.results || []) as any[]) ticketDetail[r.ticket_key] = r;
  const segs = await c.env.DB.prepare(`
    SELECT ticket_key,
           SUM((julianday(COALESCE(ended_at, datetime('now'))) - julianday(started_at)) * 86400) AS sec,
           MIN(started_at) AS first_started,
           MAX(COALESCE(ended_at, datetime('now'))) AS last_ended,
           COUNT(*) AS n
    FROM session_ticket_segments WHERE session_id = ? GROUP BY ticket_key
  `).bind(sid).all<any>();
  const conn = await getJiraConn(c.env, head.user_email);
  const results: any[] = [];
  for (const s of (segs.results || []) as any[]) {
    if (!conn) { results.push({ ticket_key: s.ticket_key, ok: false, error: "no jira" }); continue; }
    const sec = Math.max(0, Math.round(s.sec || 0));
    const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60);
    const dur = h ? `${h}h ${m}m` : `${m}m`;
    const td = ticketDetail[s.ticket_key];
    let kc: string[] = [];
    try { kc = td?.key_changes ? JSON.parse(td.key_changes) : []; } catch {}
    const text = [
      `🤖 Claude Code 세션 작업 기록`,
      td?.summary ? `요약: ${td.summary}` : `요약: ${sessionSummary}`,
      `시간: ${dur}  (${s.n}개 세그먼트)`,
      kc.length ? `주요 변경:\n- ${kc.slice(0, 5).join("\n- ")}` : "",
      `세션 링크: ${new URL(c.req.url).origin}/browse?user=${encodeURIComponent(head.user_email)}&session=${encodeURIComponent(sid)}`,
    ].filter(Boolean).join("\n");
    const r = await addComment(conn, s.ticket_key, text);
    if (r.ok && r.id) {
      await c.env.DB.prepare(
        "UPDATE session_ticket_segments SET jira_comment_id = ? WHERE session_id = ? AND ticket_key = ? AND jira_comment_id IS NULL"
      ).bind(r.id, sid, s.ticket_key).run();
    }
    results.push({ ticket_key: s.ticket_key, ok: r.ok, error: r.error, comment_id: r.id, duration: dur });
  }
  await audit(c.env, actor, "ticket_writeback", head.user_email, sid, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true, sid, results });
});

// ── 세션 시작 시 티켓 추천 (브랜치/커밋 → 후보, 본인 미완료 → 추천) ────
app.post("/api/sessions/recommendations", async (c) => {
  const actor = c.get("actor");
  const body = await c.req.json<any>().catch(() => ({}));
  const branch = String(body.branch || "");
  const remote = String(body.remote_url || "");
  const cwd = String(body.cwd || "");
  const repoRoot = String(body.repo_root || "") || cwd || null;
  const sid = body.session_id ? String(body.session_id) : "";
  const commits: string[] = Array.isArray(body.commits)
    ? body.commits.filter((x: any) => typeof x === "string").slice(0, 20)
    : [];

  // ── Persist git context early so /tracker-ticket start can read it. ──
  // (session_git was previously written only on session_end, which is too late
  //  for auto-grouping.) Upsert keeps existing fields like commits_json/diff_stat
  //  written by the stop hook later.
  if (sid && (remote || branch || repoRoot)) {
    const nowIso = new Date().toISOString();
    await c.env.DB.prepare(`
      INSERT INTO session_git (session_id, repo_root, remote_url, branch, collected_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(session_id) DO UPDATE SET
        repo_root  = COALESCE(excluded.repo_root,  session_git.repo_root),
        remote_url = COALESCE(excluded.remote_url, session_git.remote_url),
        branch     = COALESCE(excluded.branch,     session_git.branch),
        collected_at = excluded.collected_at
    `).bind(sid, repoRoot || null, remote || null, branch || null, nowIso).run();
  }

  // ── Auto-attach to existing (user, repo) group if one is open. ──
  // The orchestrator's prior /tracker-ticket start KEY created the group with
  // active_ticket_key set; new sessions joining inherit the open ticket and
  // get their own segment opened automatically.
  let autoGroup: any = null;
  if (sid) {
    try {
      const alreadyMember: any = await c.env.DB.prepare(
        "SELECT group_id FROM session_group_members WHERE session_id = ? LIMIT 1"
      ).bind(sid).first();
      let group: any = null;
      if (alreadyMember?.group_id) {
        group = await c.env.DB.prepare("SELECT * FROM session_groups WHERE id = ?")
          .bind(alreadyMember.group_id).first<any>();
      } else {
        group = await findOpenGroupByRepo(c.env, actor.email, remote || null, repoRoot || null);
        if (group) await ensureMember(c.env, group.id, sid, "worker");
      }
      if (group) {
        if (group.active_ticket_key) {
          // Open a segment for this session on the group's active ticket.
          await openSegmentForSession(c.env, sid, group.active_ticket_key, actor.email, "auto-group-attach");
        }
        autoGroup = {
          id: group.id,
          name: group.name,
          active_ticket_key: group.active_ticket_key,
          auto_attached: !alreadyMember?.group_id,
        };
      }
    } catch { /* best-effort */ }
  }
  const KEY_RE = /\b([A-Z][A-Z0-9]{1,9}-\d+)\b/g;
  const detected = new Map<string, string>();
  const add = (k: string, ev: string) => { const u = k.toUpperCase(); if (!detected.has(u)) detected.set(u, ev); };
  for (const m of branch.matchAll(KEY_RE)) add(m[1], `브랜치: ${branch}`);
  for (const cm of commits) for (const m of cm.matchAll(KEY_RE)) add(m[1], `커밋: ${cm.slice(0, 80)}`);

  const conn = await getJiraConn(c.env, actor.email);
  let openTickets: any[] = [];
  if (conn) {
    try { openTickets = await fetchAssignedOpen(conn, 30); } catch {}
  }
  const openByKey = new Map(openTickets.map((t: any) => [t.key, t]));

  // detected 후보 메타 보강
  const detectedRich: any[] = [];
  for (const [key, evidence] of detected) {
    let meta: any = openByKey.get(key);
    if (!meta && conn) { try { meta = await fetchTicket(conn, key); } catch {} }
    detectedRich.push({
      key, evidence,
      summary: meta?.summary || null,
      status: meta?.status || null,
      url: meta?.url || (conn ? `${conn.base_url.replace(/\/$/, "")}/browse/${key}` : null),
      in_assigned: openByKey.has(key),
    });
  }

  // 추천 우선순위: detected ∩ assigned > detected > assigned (top 5)
  const detectedKeys = new Set(detectedRich.map(d => d.key));
  const assignedTop = openTickets
    .filter((t: any) => !detectedKeys.has(t.key))
    .slice(0, 5)
    .map((t: any) => ({ key: t.key, summary: t.summary, status: t.status, priority: t.priority, url: t.url }));

  return c.json({
    has_jira: !!conn,
    detected: detectedRich,
    assigned_open: assignedTop,
    repo: { remote_url: remote || null, branch: branch || null },
    auto_group: autoGroup,
    hint: autoGroup?.active_ticket_key
      ? `자동 그룹 합류: ${autoGroup.name} (활성 티켓: ${autoGroup.active_ticket_key})`
      : (detectedRich.length
          ? `감지된 티켓이 있습니다. 시작: /tracker-ticket start ${detectedRich[0].key}`
          : (assignedTop.length ? "본인 미완료 티켓 중에서 선택해 시작하세요." : "관련 티켓이 감지되지 않았습니다.")),
  });
});

// ── Wiki sync (살아있는 티켓 노트, A1) ────────────────────────────────
// 세션의 segments + analysis + git context를 Confluence 위키 페이지에 누적.
// 페이지 없으면 생성, 있으면 작업 이력 섹션에 신규 항목을 prepend(최신 위).
app.post("/api/sessions/:id/wiki-sync", async (c) => {
  const actor = c.get("actor");
  const sid = c.req.param("id");
  const head: any = await c.env.DB.prepare(
    "SELECT MAX(user_email) user_email, MAX(team) team FROM events WHERE session_id = ?"
  ).bind(sid).first();
  const owner = head?.user_email || actor.email;
  if (!canSeeUser(actor, owner, head?.team)) return c.json({ error: "forbidden" }, 403);
  const conn = await getJiraConn(c.env, owner);
  if (!conn) return c.json({ error: "no jira/confluence integration on session owner" }, 503);
  // space_key 우선순위: body.space_key → owner의 tokens.confluence_space (선택) → personal space 자동 감지
  const reqBody = await c.req.json<any>().catch(() => ({}));
  let spaceKey: string | null = (reqBody && typeof reqBody.space_key === "string" && reqBody.space_key.trim()) || null;
  if (!spaceKey) {
    const pref: any = await c.env.DB.prepare(
      "SELECT meta_json FROM user_integrations WHERE user_email = ? AND kind = 'jira'"
    ).bind(owner).first();
    try {
      const meta = pref?.meta_json ? JSON.parse(pref.meta_json) : {};
      if (meta.confluence_space_key) spaceKey = String(meta.confluence_space_key);
    } catch {}
  }
  if (!spaceKey) spaceKey = await getPersonalSpaceKey(conn);
  if (!spaceKey) return c.json({ error: "no personal Confluence space accessible" }, 503);

  // 세션의 티켓 + 요약 + key_changes
  const stRows = await c.env.DB.prepare(
    "SELECT ticket_key, summary, key_changes FROM session_tickets WHERE session_id = ? ORDER BY rank ASC"
  ).bind(sid).all<any>();
  const tickets = (stRows.results || []) as any[];
  if (!tickets.length) return c.json({ ok: true, sid, skipped: "no tickets linked", results: [] });

  // 분석/git 메타
  const analysis: any = await c.env.DB.prepare(
    "SELECT summary, key_changes, category FROM session_analysis WHERE session_id = ?"
  ).bind(sid).first();
  const git: any = await c.env.DB.prepare(
    "SELECT branch, diff_stat, commits_json FROM session_git WHERE session_id = ?"
  ).bind(sid).first();

  // segment 시간 (티켓별)
  const segs = await c.env.DB.prepare(`
    SELECT ticket_key,
           SUM((julianday(COALESCE(ended_at, datetime('now'))) - julianday(started_at)) * 86400) AS sec
    FROM session_ticket_segments WHERE session_id = ? GROUP BY ticket_key
  `).bind(sid).all<any>();
  const durByKey = new Map<string, number>();
  for (const s of (segs.results || []) as any[]) durByKey.set(s.ticket_key, Math.max(0, Math.round(s.sec || 0)));

  // 작성자 표기 (owner의 이름)
  const ownerRow: any = await c.env.DB.prepare(
    "SELECT MAX(user_name) name FROM tokens WHERE user_email = ?"
  ).bind(owner).first();
  const authorName = ownerRow?.name || owner;

  const today = new Date().toISOString().slice(0, 10);
  const sessionUrl = `${new URL(c.req.url).origin}/browse?user=${encodeURIComponent(owner)}&session=${encodeURIComponent(sid)}`;
  const HISTORY_MARKER = "<!-- WORK_HISTORY -->";

  const results: any[] = [];
  for (const t of tickets) {
    const tk = t.ticket_key;
    let kc: string[] = [];
    try { kc = t.key_changes ? JSON.parse(t.key_changes) : []; } catch {}
    if (!kc.length && analysis?.key_changes) {
      try { kc = JSON.parse(analysis.key_changes); } catch {}
    }
    const summary = t.summary || analysis?.summary || "(요약 없음)";
    const sec = durByKey.get(tk) || 0;
    const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60);
    const dur = sec > 0 ? (h ? `${h}h ${m}m` : `${m}m`) : null;

    const newSection = `
      <h3>${today} · ${escapeXml(authorName)}${dur ? ` · ${dur}` : ""}${analysis?.category ? ` · <em>${escapeXml(analysis.category)}</em>` : ""}</h3>
      <p><strong>한 일:</strong> ${escapeXml(summary)}</p>
      ${kc.length ? `<ul>${kc.map(k => `<li>${escapeXml(k)}</li>`).join("")}</ul>` : ""}
      ${git?.diff_stat ? `<p><strong>변경:</strong> <code>${escapeXml(git.diff_stat)}</code>${git.branch ? ` · 브랜치 <code>${escapeXml(git.branch)}</code>` : ""}</p>` : ""}
      <p><strong>세션:</strong> <a href="${sessionUrl}">세션 열기</a></p>
    `.trim();

    // 부모 티켓(주로 Epic)이 있으면 그 페이지를 보장하고 자식으로 매달기.
    // type이 'Epic' 또는 '에픽'이거나 parent가 있으면 무조건 nest — Jira 계층 그대로 반영.
    const ticketMeta = await fetchTicket(conn, tk);
    let parentPageId: string | undefined;
    if (ticketMeta?.parent_key) {
      const parentJiraUrl = `${conn.base_url.replace(/\/$/, "")}/browse/${ticketMeta.parent_key}`;
      const ep = await ensureEpicPage(
        conn, spaceKey, ticketMeta.parent_key,
        ticketMeta.parent_summary || "",
        parentJiraUrl,
      );
      if (ep.id) parentPageId = ep.id;
    }

    // 기존 페이지 있으면 갱신, 없으면 생성
    const existing = await findTicketWikiPage(conn, spaceKey, tk);
    if (existing) {
      let body: string = existing.body || "";
      if (body.includes(HISTORY_MARKER)) {
        body = body.replace(HISTORY_MARKER, HISTORY_MARKER + "\n" + newSection);
      } else {
        // 마커 없는 기존 페이지(예: 시드된 정적 페이지) → 작업 이력 섹션 신규 추가
        body = body + `\n<h2>📅 작업 이력</h2>\n<p style="font-size:11px;color:#888">최신 작업이 위에 추가됩니다.</p>\n${HISTORY_MARKER}\n` + newSection;
      }
      const upd = await updateConfluencePageBody(conn, existing.id, existing.title, existing.version, body, parentPageId);
      results.push({ ticket_key: tk, page_url: existing.url, action: "updated", ok: upd.ok, error: upd.error || null });
    } else {
      // 생성
      const ticketSummary = ticketMeta?.summary || "";
      const initialBody = `
        <h1>${escapeXml(ticketSummary || tk)}</h1>
        <p><em>${escapeXml(tk)} 작업 노트 · 자동 갱신됨</em></p>
        <h2>📌 개요</h2>
        <p>${escapeXml(ticketSummary || "(요약 없음)")}</p>
        ${ticketMeta?.url ? `<p><a href="${ticketMeta.url}">${tk} (Jira)</a></p>` : ""}
        <h2>📅 작업 이력</h2>
        <p style="font-size:11px;color:#888">최신 작업이 위에 추가됩니다.</p>
        ${HISTORY_MARKER}
        ${newSection}
      `.trim();
      const title = `${tk} 작업 노트${ticketSummary ? " — " + ticketSummary.slice(0, 60) : ""}`;
      const created = await createConfluencePage(conn, spaceKey, title, initialBody, parentPageId);
      if (created.ok && created.url) {
        await addJiraRemoteLink(conn, tk, created.url, title);
      }
      results.push({ ticket_key: tk, page_url: created.url || null, action: "created", ok: created.ok, error: created.error || null });
    }
  }
  await audit(c.env, actor, "wiki_sync", owner, sid, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true, sid, space_key: spaceKey, results });
});

// ── Manual ticket linking ────────────────────────────────────────────────
// 사람이 LLM 분석 결과를 보정. source='manual' 행은 다음 분석 때 보존됨.
async function rebalanceWeights(env: Env, sid: string) {
  // 모든 링크의 weight 합을 1로 정규화 (manual 우선 가중치 유지하되 균등 폴백)
  const r = await env.DB.prepare("SELECT ticket_key, weight FROM session_tickets WHERE session_id = ?").bind(sid).all<any>();
  const rows = (r.results || []) as any[];
  if (!rows.length) return;
  const sum = rows.reduce((s, x) => s + (x.weight || 0), 0);
  if (sum > 0 && Math.abs(sum - 1) < 0.01) return;
  const eq = 1 / rows.length;
  for (const x of rows) {
    const w = sum > 0 ? (x.weight || 0) / sum : eq;
    await env.DB.prepare("UPDATE session_tickets SET weight = ? WHERE session_id = ? AND ticket_key = ?")
      .bind(w, sid, x.ticket_key).run();
  }
}

app.post("/api/sessions/:id/tickets", async (c) => {
  const actor = c.get("actor");
  const sid = c.req.param("id");
  const head: any = await c.env.DB.prepare(
    "SELECT MAX(user_email) user_email, MAX(team) team FROM events WHERE session_id = ?"
  ).bind(sid).first();
  if (!head?.user_email) return c.json({ error: "session not found" }, 404);
  if (!canSeeUser(actor, head.user_email, head.team)) return c.json({ error: "forbidden" }, 403);
  const body = await c.req.json<any>().catch(() => ({}));
  const rawKey = String(body.ticket_key || "").trim().toUpperCase();
  if (!/^[A-Z][A-Z0-9]{1,9}-\d+$/.test(rawKey)) return c.json({ error: "invalid ticket key (expected ABC-123)" }, 400);
  const conf = typeof body.confidence === "number" ? body.confidence : 1.0;
  const now = new Date().toISOString();
  // 다음 rank
  const maxR: any = await c.env.DB.prepare("SELECT COALESCE(MAX(rank), -1) AS r FROM session_tickets WHERE session_id = ?").bind(sid).first();
  const rank = (maxR?.r ?? -1) + 1;
  await c.env.DB.prepare(`
    INSERT INTO session_tickets (session_id, ticket_key, rank, confidence, evidence, source, weight, created_by, created_at)
    VALUES (?, ?, ?, ?, ?, 'manual', ?, ?, ?)
    ON CONFLICT(session_id, ticket_key) DO UPDATE SET
      source='manual', confidence=excluded.confidence, evidence=excluded.evidence,
      created_by=excluded.created_by, created_at=excluded.created_at
  `).bind(sid, rawKey, rank, conf, `manual:${actor.email}`, 0, actor.email, now).run();
  await rebalanceWeights(c.env, sid);
  // 티켓 메타도 actor의 jira로 캐시 (있으면)
  const conn = await getJiraConn(c.env, actor.email);
  if (conn) {
    const t = await fetchTicket(conn, rawKey);
    if (t) {
      await c.env.DB.prepare(`
        INSERT INTO jira_tickets (key, user_email, team, summary, status, assignee_email, url, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(key, user_email) DO UPDATE SET
          team=excluded.team, summary=excluded.summary, status=excluded.status,
          assignee_email=excluded.assignee_email, url=excluded.url, fetched_at=excluded.fetched_at
      `).bind(t.key, head.user_email, head.team || null, t.summary, t.status, t.assignee_email, t.url, now).run();
    }
  }
  await audit(c.env, actor, "session_ticket_add", head.user_email, sid, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true, session_id: sid, ticket_key: rawKey });
});

app.delete("/api/sessions/:id/tickets/:key", async (c) => {
  const actor = c.get("actor");
  const sid = c.req.param("id");
  const key = c.req.param("key").toUpperCase();
  const head: any = await c.env.DB.prepare(
    "SELECT MAX(user_email) user_email, MAX(team) team FROM events WHERE session_id = ?"
  ).bind(sid).first();
  if (!head?.user_email) return c.json({ error: "session not found" }, 404);
  if (!canSeeUser(actor, head.user_email, head.team)) return c.json({ error: "forbidden" }, 403);
  const r = await c.env.DB.prepare("DELETE FROM session_tickets WHERE session_id = ? AND ticket_key = ?")
    .bind(sid, key).run();
  await rebalanceWeights(c.env, sid);
  await audit(c.env, actor, "session_ticket_remove", head.user_email, sid, c.req.header("cf-connecting-ip") || null);
  return c.json({ ok: true, removed: (r as any).meta?.changes || 0 });
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
  const targetTeam = target?.team || "";
  // 한 세션이 여러 티켓에 걸치면 N행 반환 — weight로 비용 분배
  const rows = await c.env.DB.prepare(`
    SELECT a.session_id, st.ticket_key, st.confidence, st.weight, st.source,
           a.summary, a.category, a.key_changes,
           t.summary AS ticket_summary, t.status AS ticket_status, t.url AS ticket_url,
           e.started, e.last_event, e.events,
           e.input_tokens, e.output_tokens, e.cache_read_tokens, e.cache_create_tokens, e.model
    FROM session_analysis a
    LEFT JOIN session_tickets st ON st.session_id = a.session_id
    LEFT JOIN jira_tickets t ON t.key = st.ticket_key AND (t.user_email = ? OR t.team = ?)
    LEFT JOIN (
      SELECT session_id, MAX(model) model,
             MIN(ts) started, MAX(ts) last_event, COUNT(*) events,
             SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
             SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens
      FROM events GROUP BY session_id
    ) e ON e.session_id = a.session_id
    WHERE a.analyzed_at >= ?
    AND a.session_id IN (SELECT DISTINCT session_id FROM events WHERE user_email = ?)
    ORDER BY e.last_event DESC, st.rank ASC
  `).bind(email, targetTeam, since, email).all<any>();
  // weight 기준 비용 분배. ticket이 없는(분석됐지만 매칭 0) 세션은 ticket_key=null 한 행으로 1.0
  const seen = new Set<string>();
  const out = (rows.results || []).map((r: any) => {
    const w = r.weight ?? 1.0;
    const fullCost = costUsd(r);
    return { ...r, cost_usd: fullCost * w, full_cost_usd: fullCost };
  }).filter((r: any) => {
    if (r.ticket_key) return true;
    // ticket이 없는 세션 한 번만
    if (seen.has(r.session_id)) return false;
    seen.add(r.session_id); return true;
  });
  return c.json(out);
});

// ── Bulk analyze (한 사용자의 미분석 세션 일괄) ──────────────────────────
app.post("/api/users/:email/analyze-pending", async (c) => {
  const actor = c.get("actor");
  const email = c.req.param("email");
  if (email !== actor.email && !isAdmin(actor)) return c.json({ error: "forbidden" }, 403);
  if (!c.env.GEMINI_API_KEY) return c.json({ error: "GEMINI_API_KEY missing" }, 500);
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
  // 세션 단위 메타 (티켓 무관)
  const sessions = await c.env.DB.prepare(`
    SELECT g.session_id, g.branch, g.remote_url, g.diff_stat,
           e.user_email, e.team, MIN(e.ts) started, MAX(e.ts) last_event,
           COUNT(*) events,
           SUM(e.input_tokens) input_tokens, SUM(e.output_tokens) output_tokens,
           SUM(e.cache_read_tokens) cache_read_tokens, SUM(e.cache_create_tokens) cache_create_tokens,
           a.summary AS analysis_summary, a.category
    FROM session_git g
    JOIN events e ON e.session_id = g.session_id
    LEFT JOIN session_analysis a ON a.session_id = g.session_id
    WHERE g.remote_url LIKE ? AND e.ts >= ?
    GROUP BY g.session_id ORDER BY last_event DESC LIMIT 200
  `).bind(remoteLike, since).all<any>();
  // 권한 필터
  const filtered = (sessions.results || []).filter((s: any) => isAdmin(actor) ||
    (actor.role === "manager" && s.team === actor.team) ||
    s.user_email === actor.email);
  let totalCost = 0;
  for (const s of filtered) { s.cost_usd = costUsd(s); totalCost += s.cost_usd; }

  // 세션-티켓 링크 + 티켓 메타 (배치)
  const sids = filtered.map((s: any) => s.session_id);
  const linkMap = new Map<string, { key: string; weight: number; confidence: number; source: string }[]>();
  if (sids.length) {
    const ph = sids.map(() => "?").join(",");
    const lr = await c.env.DB.prepare(
      `SELECT session_id, ticket_key, weight, confidence, source FROM session_tickets WHERE session_id IN (${ph}) ORDER BY rank ASC`
    ).bind(...sids).all<any>();
    for (const r of (lr.results || [])) {
      const arr = linkMap.get(r.session_id) || [];
      arr.push({ key: r.ticket_key, weight: r.weight ?? 1, confidence: r.confidence ?? 0, source: r.source });
      linkMap.set(r.session_id, arr);
    }
  }
  const allKeys = Array.from(new Set([...linkMap.values()].flat().map(x => x.key)));
  const metaByKey: Record<string, any> = {};
  if (allKeys.length) {
    const ph = allKeys.map(() => "?").join(",");
    const tr = await c.env.DB.prepare(
      `SELECT key, MAX(summary) summary, MAX(status) status, MAX(url) url FROM jira_tickets WHERE key IN (${ph}) GROUP BY key`
    ).bind(...allKeys).all<any>();
    for (const t of (tr.results || [])) metaByKey[t.key] = t;
  }

  // 티켓별 집계 (weight로 비용 분배)
  const byTicket: Record<string, any> = {};
  for (const s of filtered) {
    const links = linkMap.get(s.session_id) || [];
    if (!links.length) {
      const k = "(미연결)";
      byTicket[k] = byTicket[k] || { ticket_key: null, ticket_summary: null, ticket_status: null, ticket_url: null, sessions: [], cost_usd: 0, users: new Set() };
      byTicket[k].sessions.push(s);
      byTicket[k].cost_usd += s.cost_usd;
      byTicket[k].users.add(s.user_email);
      continue;
    }
    for (const l of links) {
      const k = l.key;
      const meta = metaByKey[k] || {};
      byTicket[k] = byTicket[k] || { ticket_key: k, ticket_summary: meta.summary || null, ticket_status: meta.status || null, ticket_url: meta.url || null, sessions: [], cost_usd: 0, users: new Set(), avg_confidence: 0, _confSum: 0, _confN: 0 };
      byTicket[k].sessions.push({ ...s, weight: l.weight, confidence: l.confidence, source: l.source });
      byTicket[k].cost_usd += s.cost_usd * l.weight;
      byTicket[k].users.add(s.user_email);
      byTicket[k]._confSum += l.confidence; byTicket[k]._confN += 1;
    }
  }
  const tickets = Object.values(byTicket).map((t: any) => ({
    ...t,
    users: [...t.users],
    avg_confidence: t._confN ? +(t._confSum / t._confN).toFixed(2) : null,
    _confSum: undefined, _confN: undefined,
  }));

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

// ── 일일 보드 (매니저: 팀, 관리자: 전체) ──────────────────────────────────
// 각 멤버가 그날 "해야 할 일"(미완료 Jira 티켓) + "한 일"(분석된 세션) 반환
async function dailyForMembers(env: Env, members: { email: string; name: string | null; team: string | null; plan?: string | null }[], dayStart: string, dayEnd: string) {
  const out: any[] = [];
  for (const m of members) {
    // 미완료 티켓 (jira_tickets — user_email 우선, 같은 team 폴백)
    const tickets = await env.DB.prepare(`
      SELECT key, MAX(summary) summary, MAX(status) status, MAX(url) url, MAX(fetched_at) fetched_at
      FROM jira_tickets
      WHERE (user_email = ? OR team = ?)
        AND (status IS NULL OR LOWER(status) NOT IN ('done','closed','완료','resolved'))
      GROUP BY key
      ORDER BY fetched_at DESC LIMIT 20
    `).bind(m.email, m.team || "").all<any>();
    // 그날 한 일 — 분석된 세션을 (session, ticket) 단위로 펼쳐서 weight 적용
    const done = await env.DB.prepare(`
      SELECT a.session_id, st.ticket_key, st.weight, st.confidence, st.source,
             a.summary, a.category,
             t.summary AS ticket_summary, t.url AS ticket_url,
             MIN(e.ts) started, MAX(e.ts) last_event,
             SUM(e.input_tokens) input_tokens, SUM(e.output_tokens) output_tokens,
             SUM(e.cache_read_tokens) cache_read_tokens, SUM(e.cache_create_tokens) cache_create_tokens,
             MAX(e.model) model
      FROM events e
      JOIN session_analysis a ON a.session_id = e.session_id
      LEFT JOIN session_tickets st ON st.session_id = a.session_id
      LEFT JOIN jira_tickets t ON t.key = st.ticket_key AND (t.user_email = ? OR t.team = ?)
      WHERE e.user_email = ? AND e.ts >= ? AND e.ts < ?
      GROUP BY a.session_id, st.ticket_key
      ORDER BY last_event DESC, st.rank ASC
    `).bind(m.email, m.team || "", m.email, dayStart, dayEnd).all<any>();
    // 그날의 raw 활동 통계 (분석 안 된 세션도 포함)
    const stats: any = await env.DB.prepare(`
      SELECT COUNT(DISTINCT session_id) sessions, COUNT(*) events,
             SUM(input_tokens) input_tokens, SUM(output_tokens) output_tokens,
             SUM(cache_read_tokens) cache_read_tokens, SUM(cache_create_tokens) cache_create_tokens,
             MAX(model) model
      FROM events WHERE user_email = ? AND ts >= ? AND ts < ?
    `).bind(m.email, dayStart, dayEnd).first();
    // weight로 비용 분배. 티켓 없는 세션은 한 번만 출력 (ticket_key=null, weight=1)
    const seenSid = new Set<string>();
    const doneRows = (done.results || []).map((d: any) => {
      const w = d.weight ?? 1.0;
      return { ...d, weight: w, cost_usd: costUsd(d) * w, full_cost_usd: costUsd(d) };
    }).filter((d: any) => {
      if (d.ticket_key) return true;
      if (seenSid.has(d.session_id)) return false;
      seenSid.add(d.session_id); return true;
    });

    // ── 3-bucket 분류: todo / doing / done ─────────────────────────────
    // todo  = 미완료 jira 티켓 中 오늘 세션 없음
    // doing = 미완료 jira 티켓 中 오늘 세션 있음 (메타 + 오늘 세션들 묶음)
    // done  = 오늘 분석된 세션 中 (a) 티켓 없음 또는 (b) 티켓이 jira 미완료 목록에 없음 (=완료된 티켓이거나 캐시 누락)
    const openByKey = new Map<string, any>();
    for (const t of (tickets.results || []) as any[]) openByKey.set(t.key, t);
    const todaysByKey = new Map<string, any[]>();
    for (const d of doneRows) {
      if (!d.ticket_key) continue;
      const arr = todaysByKey.get(d.ticket_key) || [];
      arr.push(d); todaysByKey.set(d.ticket_key, arr);
    }
    const doing: any[] = [];
    for (const [key, sessions] of todaysByKey) {
      const meta = openByKey.get(key);
      if (!meta) continue;  // 미완료 목록에 없으면 done으로 흘림
      const cost = sessions.reduce((s, x) => s + (x.cost_usd || 0), 0);
      const dur = sessions.reduce((s, x) => {
        const d = (new Date(x.last_event).getTime() - new Date(x.started).getTime()) / 1000;
        return s + (d > 0 && d < 86400 ? Math.min(d, 14400) : 0);
      }, 0);
      doing.push({ ...meta, sessions, cost_usd: cost, duration_sec: Math.round(dur) });
      openByKey.delete(key);  // doing으로 옮긴 키는 todo에서 제거
    }
    const todoOnly = Array.from(openByKey.values());
    const doneOnly = doneRows.filter((d: any) => !d.ticket_key || !todaysByKey.has(d.ticket_key) || !doing.some(x => x.key === d.ticket_key));

    out.push({
      email: m.email, name: m.name, team: m.team, plan: m.plan || null,
      todo: todoOnly,
      doing,
      done: doneOnly,
      stats: { ...stats, cost_usd: costUsd(stats || {}) },
    });
  }
  return out;
}

function dayBounds(dateStr: string): { start: string; end: string; label: string } {
  // dateStr YYYY-MM-DD assumed in KST. Convert to UTC ISO bounds.
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateStr || "");
  const now = new Date();
  let y: number, mo: number, d: number;
  if (m) { y = +m[1]; mo = +m[2]; d = +m[3]; }
  else {
    // KST today
    const kst = new Date(now.getTime() + 9 * 3600_000);
    y = kst.getUTCFullYear(); mo = kst.getUTCMonth() + 1; d = kst.getUTCDate();
  }
  // KST start = 00:00 KST = previous day 15:00 UTC
  const start = new Date(Date.UTC(y, mo - 1, d, 0, 0, 0) - 9 * 3600_000);
  const end = new Date(start.getTime() + 86400_000);
  const label = `${y}-${String(mo).padStart(2,"0")}-${String(d).padStart(2,"0")}`;
  return { start: start.toISOString(), end: end.toISOString(), label };
}

// 팀 WBS / Gantt: 팀원들의 미완료 Jira 티켓을 라이브로 집계 (Jira 연동된 멤버만)
app.get("/api/teams/:team/wbs", async (c) => {
  const actor = c.get("actor");
  const team = c.req.param("team");
  if (!isAdmin(actor) && !(actor.role === "manager" && actor.team === team)) {
    return c.json({ error: "forbidden" }, 403);
  }
  const mem = await c.env.DB.prepare(
    "SELECT user_email email, MAX(user_name) name FROM tokens WHERE team = ? AND revoked_at IS NULL GROUP BY user_email"
  ).bind(team).all<any>();
  const members = (mem.results || []) as any[];
  const tickets: any[] = [];
  let withJira = 0, withoutJira = 0;
  for (const m of members) {
    const conn = await getJiraConn(c.env, m.email);
    if (!conn) { withoutJira++; continue; }
    withJira++;
    try {
      const ts = await fetchAssignedOpen(conn, 100);
      for (const t of ts) tickets.push({ ...t, owner_email: m.email, owner_name: m.name });
    } catch {}
  }
  return c.json({ team, members: members.length, with_jira: withJira, without_jira: withoutJira, tickets });
});

app.get("/api/teams/:team/daily", async (c) => {
  const actor = c.get("actor");
  const team = c.req.param("team");
  if (!isAdmin(actor) && !(actor.role === "manager" && actor.team === team)) {
    return c.json({ error: "forbidden" }, 403);
  }
  const b = dayBounds(c.req.query("date") || "");
  // 팀 멤버 = tokens에 등록된 활성 사용자
  const mem = await c.env.DB.prepare(
    "SELECT user_email email, MAX(user_name) name, MAX(team) team, MAX(plan) plan FROM tokens WHERE team = ? AND revoked_at IS NULL GROUP BY user_email"
  ).bind(team).all<any>();
  const members = (mem.results || []) as any[];
  const rows = await dailyForMembers(c.env, members, b.start, b.end);
  return c.json({ date: b.label, team, members: rows });
});

// 단일 사용자 일일 보드 (본인 또는 admin/manager 가시 범위)
app.get("/api/users/:email/daily", async (c) => {
  const actor = c.get("actor");
  const email = c.req.param("email");
  const target: any = await c.env.DB.prepare(
    "SELECT MAX(team) team, MAX(user_name) name FROM tokens WHERE user_email = ? AND revoked_at IS NULL"
  ).bind(email).first();
  if (!canSeeUser(actor, email, target?.team)) return c.json({ error: "forbidden" }, 403);
  const planRow: any = await c.env.DB.prepare(
    "SELECT plan FROM tokens WHERE user_email = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1"
  ).bind(email).first();
  const b = dayBounds(c.req.query("date") || "");
  const rows = await dailyForMembers(c.env, [{ email, name: target?.name || null, team: target?.team || null, plan: planRow?.plan || null }], b.start, b.end);
  return c.json({ date: b.label, member: rows[0] || null });
});

app.get("/api/admin/daily", async (c) => {
  const actor = c.get("actor");
  if (!isAdmin(actor)) return c.json({ error: "forbidden" }, 403);
  const b = dayBounds(c.req.query("date") || "");
  const mem = await c.env.DB.prepare(
    "SELECT user_email email, MAX(user_name) name, MAX(team) team, MAX(plan) plan FROM tokens WHERE revoked_at IS NULL GROUP BY user_email"
  ).all<any>();
  const members = (mem.results || []) as any[];
  const rows = await dailyForMembers(c.env, members, b.start, b.end);
  // 팀별 그룹
  const byTeam: Record<string, any[]> = {};
  for (const r of rows) {
    const k = r.team || "(unassigned)";
    (byTeam[k] = byTeam[k] || []).push(r);
  }
  return c.json({ date: b.label, teams: Object.entries(byTeam).map(([team, members]) => ({ team, members })) });
});

// "Whoami" — useful debugging for client setup
app.get("/api/me", async (c) => {
  const a = c.get("actor");
  let plan: string | null = null;
  try {
    const r: any = await c.env.DB.prepare(
      "SELECT plan FROM tokens WHERE user_email = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1"
    ).bind(a.email).first();
    plan = r?.plan || null;
  } catch {}
  return c.json({ email: a.email, name: a.name, team: a.team, role: a.role, via: a.via, is_admin: a.role === "admin", plan });
});

// 사용자가 등록한 플랜 조회/저장 (본인 또는 admin)
const PLAN_IDS = new Set(["pro", "max-5x", "max-20x", "team", "api"]);
app.get("/api/users/:email/registered-plan", async (c) => {
  const actor = c.get("actor");
  const email = c.req.param("email");
  const target: any = await c.env.DB.prepare(
    "SELECT MAX(team) team FROM events WHERE user_email = ?"
  ).bind(email).first();
  if (!canSeeUser(actor, email, target?.team)) return c.json({ error: "forbidden" }, 403);
  const row: any = await c.env.DB.prepare(
    "SELECT plan, plan_updated_at FROM tokens WHERE user_email = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1"
  ).bind(email).first();
  return c.json({ email, plan: row?.plan || null, plan_updated_at: row?.plan_updated_at || null });
});
app.put("/api/users/:email/registered-plan", async (c) => {
  const actor = c.get("actor");
  const email = c.req.param("email");
  if (email !== actor.email && !isAdmin(actor)) return c.json({ error: "forbidden" }, 403);
  const body = await c.req.json<any>().catch(() => ({}));
  const plan = body.plan === null || body.plan === "" ? null : String(body.plan);
  if (plan !== null && !PLAN_IDS.has(plan)) return c.json({ error: "invalid plan id" }, 400);
  await c.env.DB.prepare(
    "UPDATE tokens SET plan = ?, plan_updated_at = ? WHERE user_email = ? AND revoked_at IS NULL"
  ).bind(plan, new Date().toISOString(), email).run();
  return c.json({ ok: true, email, plan });
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

ask_secret() {
  local prompt="\$1" var
  printf "\\033[1m%s\\033[0m " "\$prompt" >&3
  stty -echo <&3 2>/dev/null || true
  IFS= read -r var <&3 || var=""
  stty echo <&3 2>/dev/null || true
  printf "\\n" >&3
  printf "%s" "\$var"
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

# 4) (선택) Jira 연결
echo
bold "🎟  Jira 연결 (선택)"
echo "세션을 Jira 티켓에 자동 매칭하고 작업 요약을 댓글로 자동 작성합니다."
echo "토큰 발급: https://id.atlassian.com/manage-profile/security/api-tokens"
echo "(나중에 Claude Code 안에서 /tracker-jira set ... 으로도 가능. 건너뛰려면 Enter)"
echo
JIRA_URL="\$(ask 'Jira base URL (예: https://aptner.atlassian.net)' '')"
if [ -n "\$JIRA_URL" ]; then
  JIRA_EMAIL="\$(ask 'Jira 계정 email' "\$EMAIL")"
  JIRA_TOKEN="\$(ask_secret 'Jira API 토큰:')"
  if [ -n "\$JIRA_TOKEN" ]; then
    bold "🔎 Jira 자격증명 검증·저장 중..."
    JIRA_BODY="{\\"base_url\\":\\"\$JIRA_URL\\",\\"email\\":\\"\$JIRA_EMAIL\\",\\"token\\":\\"\$JIRA_TOKEN\\"}"
    JIRA_RESP=\$(curl -s -X POST -H "Authorization: Bearer \$TOKEN" -H "Content-Type: application/json" -d "\$JIRA_BODY" "\$BASE/api/integrations/jira")
    if echo "\$JIRA_RESP" | grep -q '"ok":true'; then
      DISPLAY_NAME=\$(echo "\$JIRA_RESP" | sed -n 's/.*"displayName":"\\([^"]*\\)".*/\\1/p')
      PROJECTS=\$(echo "\$JIRA_RESP"   | sed -n 's/.*"projectsCount":\\([0-9]*\\).*/\\1/p')
      green "✅ Jira 연결: \${DISPLAY_NAME:-?} · \${PROJECTS:-?} projects"
      mkdir -p "\$HOME/.claude" && date -u +%FT%TZ > "\$HOME/.claude/.tracker-jira-nudged"
    else
      red "❌ Jira 연결 실패: \$JIRA_RESP"
      echo "   Claude Code 안에서 다시 시도: /tracker-jira set --url=... --email=... --token=..."
    fi
    unset JIRA_TOKEN JIRA_BODY JIRA_RESP
  fi
fi

# 5) (선택) 백필
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
