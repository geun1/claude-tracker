// Server-side waste-pattern detection + model comparison + health score.
// Port of subset of getagentseal/codeburn (optimize.ts + compare-stats.ts)
// adapted to read from D1 (events + messages) instead of local jsonl.
//
// Scope (Phase 1, server-only):
//   - Junk Reads, Duplicate Reads, Low Read/Edit Ratio, Cache Bloat,
//     Low-Worth Sessions, Context Bloat, Session Outliers
//   - Health score (A-F) from finding impacts
//   - Compare: aggregate per model + 7 metrics
//
// Filesystem-dependent rules (Ghost agents/skills/commands, Unused MCP,
// Bloated CLAUDE.md, Bash Bloat) are deferred to Phase 2 — require a
// client-side hook to upload settings/inventory.
//
// Cost rate inference: we attribute 70% of session cost to input tokens to
// derive a $/token rate, matching codeburn's convention.

import { classifyTurn, countRetries, turnHasEdits, TOOL_SETS, TaskCategory } from "./classifier";

const JUNK_PATTERN = /(^|\/)(node_modules|\.git|dist|build|__pycache__|\.next|\.nuxt|\.turbo|\.cache|coverage|out|target|vendor|\.venv|venv|env|\.tox|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.gradle|\.idea|\.vscode-test)(\/|$)/i;

const AVG_TOKENS_PER_READ        = 600;
const HEALTH_WEIGHT_HIGH         = 15;
const HEALTH_WEIGHT_MEDIUM       = 7;
const HEALTH_WEIGHT_LOW          = 3;
const HEALTH_MAX_PENALTY         = 80;
const URGENCY_WEIGHTS = { high: 1, medium: 0.6, low: 0.3 } as const;

export type Impact = "high" | "medium" | "low";

export type Finding = {
  rule: string;
  title: string;
  impact: Impact;
  tokensSaved: number;
  usdSaved: number;
  detail: string;
  fix: { destination: "claude-md" | "session-opener" | "prompt" | "command" | "shell-config" | "info"; content: string };
  evidence?: Record<string, any>;
  trend?: "improving" | "resolved" | "active";
};

export type OptimizeReport = {
  user_email: string;
  days: number;
  sessions_scanned: number;
  total_cost_usd: number;
  total_tokens: number;
  cost_per_token: number;
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  findings: Finding[];
  category_breakdown: Record<TaskCategory, { turns: number; cost: number; edit_turns: number; one_shot_turns: number; retries: number }>;
};

type Turn = {
  userMessage: string;
  toolGroups: string[][];      // per-assistant-message tool name groups (ordered)
  reads: string[];              // file paths read
  edits: string[];              // file paths written/edited
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheCreateTokens: number;
  apiCalls: number;
  cost: number;                 // approxCost over this turn's assistant calls
  category: TaskCategory;
  retries: number;
  hasEdits: boolean;
};

type SessionAgg = {
  session_id: string;
  cwd: string;
  model: string;
  started: string;
  last_event: string;
  total_cost: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_create_tokens: number;
  api_calls: number;
  edit_turns: number;
  one_shot_turns: number;
  retries: number;
  turns: Turn[];
};

// ─────────────────────────────────────────────────────────────────────────────
// Aggregation: load sessions + reconstruct turns from messages
// ─────────────────────────────────────────────────────────────────────────────

function safeParseTools(json: string | null | undefined): { name: string; input?: any }[] {
  if (!json) return [];
  try {
    const a = JSON.parse(json);
    if (!Array.isArray(a)) return [];
    return a.filter((x: any) => x && typeof x.name === "string");
  } catch { return []; }
}

export async function loadUserSessions(
  env: any,
  userEmail: string,
  days: number,
  maxSessions: number = 100,
): Promise<{ sessions: SessionAgg[]; totalCost: number }> {
  const since = new Date(Date.now() - days * 86400_000).toISOString();
  const sessionRows = await env.DB.prepare(`
    SELECT session_id,
           MAX(cwd) AS cwd, MAX(model) AS model,
           MIN(ts) AS started, MAX(ts) AS last_event,
           COUNT(*) AS api_calls,
           SUM(input_tokens) AS input_tokens,
           SUM(output_tokens) AS output_tokens,
           SUM(cache_read_tokens) AS cache_read_tokens,
           SUM(cache_create_tokens) AS cache_create_tokens
    FROM events
    WHERE user_email = ? AND ts > ?
    GROUP BY session_id
    HAVING (input_tokens + output_tokens + cache_read_tokens + cache_create_tokens) > 0
    ORDER BY started DESC
    LIMIT ?
  `).bind(userEmail, since, maxSessions).all();

  const sessions: SessionAgg[] = [];
  let totalCost = 0;

  for (const row of (sessionRows.results || []) as any[]) {
    // Pull cost from events using existing costUsd helper if accessible; for now
    // re-derive in caller via Worker import. We sum tokens here and let the
    // caller multiply by a model-specific rate. Cost summed via separate query
    // for accuracy:
    const c: any = await env.DB.prepare(`
      SELECT input_tokens, output_tokens, cache_read_tokens, cache_create_tokens, model
      FROM events WHERE session_id = ?
    `).bind(row.session_id).all();
    // costUsd is defined in index.ts; we recompute approximate cost from pricing
    // table. For Phase 1, derive cost from a flat $3/1M input + $15/1M output as
    // a conservative average — caller can swap to real costUsd if needed.
    let sessionCost = 0;
    for (const e of (c.results || []) as any[]) {
      sessionCost += approxCost(e);
    }
    totalCost += sessionCost;

    const msgs = await env.DB.prepare(`
      SELECT seq, role, text, tool_calls_json, model,
             input_tokens, output_tokens, cache_read_tokens, cache_create_tokens
      FROM messages
      WHERE session_id = ?
      ORDER BY seq ASC
    `).bind(row.session_id).all();

    const turns = reconstructTurns((msgs.results || []) as any[], row.model);

    sessions.push({
      session_id: row.session_id,
      cwd: row.cwd || "",
      model: row.model || "",
      started: row.started,
      last_event: row.last_event,
      total_cost: sessionCost,
      input_tokens: Number(row.input_tokens) || 0,
      output_tokens: Number(row.output_tokens) || 0,
      cache_read_tokens: Number(row.cache_read_tokens) || 0,
      cache_create_tokens: Number(row.cache_create_tokens) || 0,
      api_calls: Number(row.api_calls) || 0,
      edit_turns: turns.filter(t => t.hasEdits).length,
      one_shot_turns: turns.filter(t => t.hasEdits && t.retries === 0).length,
      retries: turns.reduce((s, t) => s + t.retries, 0),
      turns,
    });
  }

  return { sessions, totalCost };
}

function reconstructTurns(messages: any[], sessionModel: string): Turn[] {
  const turns: Turn[] = [];
  let cur: Turn | null = null;
  for (const m of messages) {
    if (m.role === "user") {
      if (cur) turns.push(cur);
      cur = {
        userMessage: m.text || "",
        toolGroups: [],
        reads: [],
        edits: [],
        inputTokens: 0,
        outputTokens: 0,
        cacheReadTokens: 0,
        cacheCreateTokens: 0,
        apiCalls: 0,
        cost: 0,
        category: "conversation",
        retries: 0,
        hasEdits: false,
      };
    } else if (m.role === "assistant" && cur) {
      const tools = safeParseTools(m.tool_calls_json);
      const names = tools.map(t => t.name);
      if (names.length) cur.toolGroups.push(names);
      for (const t of tools) {
        if (TOOL_SETS.READ_TOOLS.has(t.name)) {
          const p = t.input?.file_path || t.input?.path || t.input?.pattern;
          if (typeof p === "string") cur.reads.push(p);
        }
        if (TOOL_SETS.EDIT_TOOLS.has(t.name)) {
          const p = t.input?.file_path || t.input?.path;
          if (typeof p === "string") cur.edits.push(p);
        }
      }
      cur.inputTokens        += Number(m.input_tokens) || 0;
      cur.outputTokens       += Number(m.output_tokens) || 0;
      cur.cacheReadTokens    += Number(m.cache_read_tokens) || 0;
      cur.cacheCreateTokens  += Number(m.cache_create_tokens) || 0;
      cur.apiCalls += 1;
      cur.cost += approxCost({ ...m, model: m.model || sessionModel });
    }
  }
  if (cur) turns.push(cur);
  // Post-process: classify + retry count + edits flag
  for (const t of turns) {
    t.retries  = countRetries(t.toolGroups);
    t.hasEdits = turnHasEdits(t.toolGroups);
    t.category = classifyTurn({ userMessage: t.userMessage, callsTools: t.toolGroups });
  }
  return turns;
}

// Pricing: conservative average. Real prices vary per model; for $/token rate
// inference downstream we'll use the (cost, input_tokens) pair, so accuracy of
// the absolute number matters less than internal consistency.
function approxCost(e: any): number {
  // 매우 단순한 근사. Real pricing.ts에는 model별 정확한 단가가 있지만
  // optimize report에서는 비교를 위한 단위 일관성이 핵심.
  const model = String(e.model || "").toLowerCase();
  let inRate = 3, outRate = 15, cwRate = 3.75, crRate = 0.3;  // $/1M
  if (model.includes("opus"))      { inRate = 15; outRate = 75; cwRate = 18.75; crRate = 1.5; }
  else if (model.includes("haiku")){ inRate = 0.8; outRate = 4;  cwRate = 1.0;  crRate = 0.08; }
  return (
    (Number(e.input_tokens)        || 0) * inRate  / 1_000_000 +
    (Number(e.output_tokens)       || 0) * outRate / 1_000_000 +
    (Number(e.cache_create_tokens) || 0) * cwRate  / 1_000_000 +
    (Number(e.cache_read_tokens)   || 0) * crRate  / 1_000_000
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Detection rules
// ─────────────────────────────────────────────────────────────────────────────

function pickImpact(metric: number, low: number, med: number): Impact {
  if (metric >= med) return "high";
  if (metric >= low) return "medium";
  return "low";
}

function tokenToDollar(tokens: number, costPerToken: number): number {
  return Math.round(tokens * costPerToken * 100) / 100;
}

function detectJunkReads(sessions: SessionAgg[], costPerToken: number): Finding | null {
  let count = 0;
  const examples: string[] = [];
  for (const s of sessions) for (const t of s.turns) for (const p of t.reads) {
    if (JUNK_PATTERN.test(p)) {
      count++;
      if (examples.length < 5) examples.push(p);
    }
  }
  if (count < 3) return null;
  const tokens = count * AVG_TOKENS_PER_READ;
  return {
    rule: "junk-reads",
    title: `${count}개의 정크 디렉토리 Read (node_modules, .git, dist 등)`,
    impact: pickImpact(count, 5, 20),
    tokensSaved: tokens,
    usdSaved: tokenToDollar(tokens, costPerToken),
    detail: `예: ${examples.slice(0, 3).join(", ")}`,
    evidence: { count, examples },
    fix: {
      destination: "claude-md",
      content: "# 정크 디렉토리는 읽지 마라\nnode_modules/, .git/, dist/, build/, .next/, __pycache__/, coverage/, target/, venv/, .venv/, vendor/ 등의 디렉토리는 Read/Grep/Glob 대상에서 제외하라. Glob/Grep 시 명시적으로 제외하거나, 소스 디렉토리만 지정하라.",
    },
  };
}

function detectDuplicateReads(sessions: SessionAgg[], costPerToken: number): Finding | null {
  let dupCount = 0;
  const topExamples: { path: string; n: number }[] = [];
  for (const s of sessions) {
    const counts = new Map<string, number>();
    for (const t of s.turns) for (const p of t.reads) counts.set(p, (counts.get(p) || 0) + 1);
    for (const [path, n] of counts) {
      if (n > 1) {
        dupCount += n - 1;
        if (topExamples.length < 5) topExamples.push({ path, n });
      }
    }
  }
  if (dupCount < 5) return null;
  const tokens = dupCount * AVG_TOKENS_PER_READ;
  return {
    rule: "duplicate-reads",
    title: `${dupCount}회의 중복 파일 Read`,
    impact: pickImpact(dupCount, 10, 30),
    tokensSaved: tokens,
    usdSaved: tokenToDollar(tokens, costPerToken),
    detail: topExamples.slice(0, 3).map(e => `${e.path} (${e.n}회)`).join(", "),
    evidence: { duplicate_extra_reads: dupCount, top_examples: topExamples },
    fix: {
      destination: "claude-md",
      content: "# 한 세션에서 같은 파일을 반복해서 Read 하지 마라\n이미 읽은 파일은 추가 Read 대신 line range를 명시한 grep이나 메모리상의 내용을 활용하라. 같은 파일을 두 번째 읽기 전에 자신에게 물어라: 정말 새 내용이 필요한가, 아니면 처음 읽은 내용을 잊었는가?",
    },
  };
}

function detectLowReadEditRatio(sessions: SessionAgg[], costPerToken: number): Finding | null {
  let reads = 0, edits = 0;
  for (const s of sessions) for (const t of s.turns) {
    reads += t.reads.length;
    edits += t.edits.length;
  }
  if (edits < 5) return null;
  const ratio = reads / edits;
  if (ratio >= 4) return null;
  const target = Math.round(edits * 4);
  const tokens = Math.max(0, target - reads) * AVG_TOKENS_PER_READ;
  return {
    rule: "low-read-edit-ratio",
    title: `Read/Edit 비율이 낮음 (${ratio.toFixed(1)}:1, 권장 4:1)`,
    impact: ratio < 2 ? "high" : ratio < 3 ? "medium" : "low",
    tokensSaved: tokens,
    usdSaved: tokenToDollar(tokens, costPerToken),
    detail: `${reads} reads / ${edits} edits — 코드를 충분히 이해하지 않고 편집하는 패턴 가능성`,
    evidence: { reads, edits, ratio: Math.round(ratio * 10) / 10 },
    fix: {
      destination: "claude-md",
      content: "# 편집 전에 충분히 읽어라\n파일을 편집(Edit/Write)하기 전에 최소 그 파일과 호출하는 곳을 읽어 컨텍스트를 잡아라. 권장 비율: 편집 1회당 최소 4회 Read/Grep. 추측 편집은 retry를 부르고 결과적으로 더 비싸진다.",
    },
  };
}

function detectCacheBloat(sessions: SessionAgg[], costPerToken: number): Finding | null {
  // Per-API-call median cache_create across all calls in window.
  const cw: number[] = [];
  for (const s of sessions) {
    if (s.api_calls === 0) continue;
    cw.push(s.cache_create_tokens / s.api_calls);
  }
  if (cw.length < 5) return null;
  cw.sort((a, b) => a - b);
  const median = cw[Math.floor(cw.length / 2)];
  const p25 = cw[Math.floor(cw.length * 0.25)];
  const baseline = Math.max(p25, 50_000);
  if (median <= baseline * 1.4) return null;
  const totalCalls = sessions.reduce((s, x) => s + x.api_calls, 0);
  const tokens = Math.round((median - baseline) * totalCalls);
  return {
    rule: "cache-bloat",
    title: `평균 캐시 write가 baseline보다 ${Math.round((median / baseline - 1) * 100)}% 큼`,
    impact: median - baseline > 15_000 ? "high" : "medium",
    tokensSaved: tokens,
    usdSaved: tokenToDollar(tokens, costPerToken),
    detail: `median ${Math.round(median).toLocaleString()} vs baseline ${Math.round(baseline).toLocaleString()} per call`,
    evidence: { median_cw_per_call: Math.round(median), baseline, api_calls: totalCalls },
    fix: {
      destination: "info",
      content: "캐시 write 토큰이 비정상적으로 크다. CLAUDE.md / system prompt / @-import 파일이 매 호출마다 캐시를 다시 채우고 있는지 확인하라. 200줄 이하로 줄이거나 5분 TTL 안에 재호출하라.",
    },
  };
}

function detectLowWorthSessions(sessions: SessionAgg[], costPerToken: number): Finding | null {
  const candidates: { sid: string; cost: number; reason: string; tokens: number }[] = [];
  for (const s of sessions) {
    const tokens = s.input_tokens + s.output_tokens + s.cache_read_tokens + s.cache_create_tokens;
    const threshold = s.edit_turns === 0 ? 3 : 2;
    if (s.total_cost < threshold) continue;
    if (s.edit_turns === 0) {
      candidates.push({ sid: s.session_id, cost: s.total_cost, reason: "edit 0", tokens });
    } else if (s.retries >= 3) {
      const retryFrac = s.retries / Math.max(1, s.edit_turns);
      candidates.push({ sid: s.session_id, cost: s.total_cost, reason: `retries ${s.retries}`, tokens: Math.round(tokens * Math.min(1, retryFrac)) });
    } else if (s.edit_turns > 0 && s.one_shot_turns === 0) {
      candidates.push({ sid: s.session_id, cost: s.total_cost, reason: "one-shot 0", tokens: Math.round(tokens * 0.5) });
    }
  }
  if (candidates.length === 0) return null;
  const totalTokens = candidates.reduce((s, c) => s + c.tokens, 0);
  const totalCost = candidates.reduce((s, c) => s + c.cost, 0);
  return {
    rule: "low-worth-sessions",
    title: `${candidates.length}개의 저가치 고비용 세션`,
    impact: candidates.length >= 10 || totalCost >= 50 ? "high" : candidates.length <= 2 && totalCost < 10 ? "low" : "medium",
    tokensSaved: totalTokens,
    usdSaved: tokenToDollar(totalTokens, costPerToken),
    detail: `총 $${totalCost.toFixed(2)} — edit 없음, retry 과다, 또는 one-shot 0`,
    evidence: { count: candidates.length, total_cost: totalCost, top: candidates.slice(0, 5) },
    fix: {
      destination: "session-opener",
      content: "이 세션에서 끝낼 구체적인 deliverable을 먼저 한 문장으로 적어줘. 시도가 두 번 실패하면 멈추고 접근을 재검토하자.",
    },
  };
}

function detectContextBloat(sessions: SessionAgg[], costPerToken: number): Finding | null {
  const offenders: { sid: string; effective: number; ratio: number; over: number }[] = [];
  for (const s of sessions) {
    const effective = s.input_tokens + s.cache_read_tokens * 0.1 + s.cache_create_tokens * 1.25;
    if (effective < 75_000) continue;
    const ratio = s.output_tokens > 0 ? effective / s.output_tokens : Infinity;
    if (ratio < 25) continue;
    const over = Math.max(0, s.input_tokens - s.output_tokens * 15);
    if (over <= 0) continue;
    offenders.push({ sid: s.session_id, effective: Math.round(effective), ratio: Math.round(ratio * 10) / 10, over });
  }
  if (offenders.length === 0) return null;
  const total = offenders.reduce((s, o) => s + o.over, 0);
  return {
    rule: "context-bloat",
    title: `${offenders.length}개의 컨텍스트 비대 세션 (input/output > 25:1)`,
    impact: offenders.length >= 10 || total >= 500_000 ? "high" : offenders.length <= 2 && total < 200_000 ? "low" : "medium",
    tokensSaved: total,
    usdSaved: tokenToDollar(total, costPerToken),
    detail: `${offenders.length}개 세션에서 input이 output 대비 25배 이상`,
    evidence: { count: offenders.length, top: offenders.slice(0, 5) },
    fix: {
      destination: "session-opener",
      content: "이 세션은 새로 시작했고, 컨텍스트를 좁게 유지하겠다: 지금 풀려는 문제 한 문장 + 관련 파일 ≤ 3개만 우선 읽어줘. 무관한 코드/디렉토리는 건드리지 마.",
    },
  };
}

function detectSessionOutliers(sessions: SessionAgg[], costPerToken: number): Finding | null {
  // Group by project (cwd 상단 디렉토리)
  const byProj = new Map<string, SessionAgg[]>();
  for (const s of sessions) {
    const proj = s.cwd.split("/").slice(0, 4).join("/") || "unknown";
    (byProj.get(proj) || byProj.set(proj, []).get(proj)!).push(s);
  }
  const outliers: { sid: string; cost: number; avg: number; project: string }[] = [];
  for (const [proj, list] of byProj) {
    if (list.length < 3) continue;
    const avg = list.reduce((s, x) => s + x.total_cost, 0) / list.length;
    for (const s of list) {
      if (s.total_cost > avg * 2 && s.total_cost >= 1) {
        outliers.push({ sid: s.session_id, cost: s.total_cost, avg, project: proj });
      }
    }
  }
  if (outliers.length === 0) return null;
  const excess = outliers.reduce((s, o) => s + (o.cost - o.avg), 0);
  // Convert excess USD → tokens via inverse cost rate
  const tokens = costPerToken > 0 ? Math.round(excess / costPerToken) : 0;
  return {
    rule: "session-outliers",
    title: `${outliers.length}개의 비용 outlier 세션 (프로젝트 평균 2배 이상)`,
    impact: outliers.length >= 3 || excess >= 10 ? "high" : "medium",
    tokensSaved: tokens,
    usdSaved: Math.round(excess * 100) / 100,
    detail: `excess $${excess.toFixed(2)}`,
    evidence: { count: outliers.length, top: outliers.slice(0, 5).map(o => ({ ...o, cost: Math.round(o.cost * 100) / 100, avg: Math.round(o.avg * 100) / 100 })) },
    fix: {
      destination: "session-opener",
      content: "이전 세션이 이 프로젝트 평균보다 2배 이상 비쌌어. 이번엔 컨텍스트를 좁게: 한 가지 변경만 하고, 첫 동작하는 패치에서 멈추자.",
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Health score
// ─────────────────────────────────────────────────────────────────────────────

function computeScore(findings: Finding[]): { score: number; grade: OptimizeReport["grade"] } {
  const penalty = findings.reduce((s, f) => s + (f.impact === "high" ? HEALTH_WEIGHT_HIGH : f.impact === "medium" ? HEALTH_WEIGHT_MEDIUM : HEALTH_WEIGHT_LOW), 0);
  const score = Math.max(0, 100 - Math.min(HEALTH_MAX_PENALTY, penalty));
  const grade: OptimizeReport["grade"] =
    score >= 90 ? "A" : score >= 75 ? "B" : score >= 55 ? "C" : score >= 30 ? "D" : "F";
  return { score, grade };
}

function rankFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const aw = URGENCY_WEIGHTS[a.impact] * 0.5 + Math.min(1, a.tokensSaved / 5_000_000) * 0.5;
    const bw = URGENCY_WEIGHTS[b.impact] * 0.5 + Math.min(1, b.tokensSaved / 5_000_000) * 0.5;
    return bw - aw;
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level: run all detectors and produce report
// ─────────────────────────────────────────────────────────────────────────────

export async function runOptimize(env: any, userEmail: string, days: number = 30): Promise<OptimizeReport> {
  const { sessions, totalCost } = await loadUserSessions(env, userEmail, days);
  const totalTokens = sessions.reduce((s, x) => s + x.input_tokens + x.output_tokens + x.cache_read_tokens + x.cache_create_tokens, 0);
  // $/token rate. Codeburn uses (cost * 0.7) / input_tokens, which inflates
  // savings when cache_read tokens dominate (typical Claude Code usage).
  // Average over total tokens is the more honest unit cost for our case.
  const costPerToken = totalTokens > 0 ? totalCost / totalTokens : 0;

  // Category breakdown
  const cats: Record<string, any> = {};
  for (const s of sessions) for (const t of s.turns) {
    const k = t.category;
    if (!cats[k]) cats[k] = { turns: 0, cost: 0, edit_turns: 0, one_shot_turns: 0, retries: 0 };
    cats[k].turns++;
    cats[k].cost += t.cost;
    if (t.hasEdits) cats[k].edit_turns++;
    if (t.hasEdits && t.retries === 0) cats[k].one_shot_turns++;
    cats[k].retries += t.retries;
  }

  const found: Finding[] = [];
  const push = (f: Finding | null) => { if (f && f.tokensSaved > 0) found.push(f); };
  push(detectJunkReads(sessions, costPerToken));
  push(detectDuplicateReads(sessions, costPerToken));
  push(detectLowReadEditRatio(sessions, costPerToken));
  push(detectCacheBloat(sessions, costPerToken));
  push(detectLowWorthSessions(sessions, costPerToken));
  push(detectContextBloat(sessions, costPerToken));
  push(detectSessionOutliers(sessions, costPerToken));

  const { score, grade } = computeScore(found);

  return {
    user_email: userEmail,
    days,
    sessions_scanned: sessions.length,
    total_cost_usd: Math.round(totalCost * 100) / 100,
    total_tokens: totalTokens,
    cost_per_token: costPerToken,
    score,
    grade,
    findings: rankFindings(found),
    category_breakdown: cats,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Compare: per-model aggregates + 7 metrics
// ─────────────────────────────────────────────────────────────────────────────

export type ModelStats = {
  model: string;
  calls: number;
  cost: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_create_tokens: number;
  total_turns: number;
  edit_turns: number;
  one_shot_turns: number;
  retries: number;
};

export type ComparisonRow = {
  section: "Performance" | "Efficiency";
  label: string;
  valueA: number | null;
  valueB: number | null;
  format: "percent" | "decimal" | "cost" | "number";
  higherIsBetter: boolean;
  winner: "a" | "b" | "tie" | "none";
};

export async function aggregateModelStats(env: any, userEmail: string, days: number): Promise<ModelStats[]> {
  const { sessions } = await loadUserSessions(env, userEmail, days);
  const m = new Map<string, ModelStats>();
  const ensure = (model: string) => {
    let s = m.get(model);
    if (!s) {
      s = { model, calls: 0, cost: 0, input_tokens: 0, output_tokens: 0, cache_read_tokens: 0, cache_create_tokens: 0, total_turns: 0, edit_turns: 0, one_shot_turns: 0, retries: 0 };
      m.set(model, s);
    }
    return s;
  };
  for (const s of sessions) {
    const ms = ensure(s.model || "unknown");
    ms.total_turns += s.turns.length;
    ms.edit_turns += s.edit_turns;
    ms.one_shot_turns += s.one_shot_turns;
    ms.retries += s.retries;
    ms.calls += s.api_calls;
    ms.cost += s.total_cost;
    ms.input_tokens += s.input_tokens;
    ms.output_tokens += s.output_tokens;
    ms.cache_read_tokens += s.cache_read_tokens;
    ms.cache_create_tokens += s.cache_create_tokens;
  }
  return [...m.values()].sort((a, b) => b.cost - a.cost);
}

function pickWinner(a: number | null, b: number | null, higherIsBetter: boolean): ComparisonRow["winner"] {
  if (a === null || b === null) return "none";
  if (a === b) return "tie";
  return higherIsBetter ? (a > b ? "a" : "b") : (a < b ? "a" : "b");
}

export function compareModels(a: ModelStats, b: ModelStats): ComparisonRow[] {
  const safe = (num: number, den: number, mult: number = 1) => den > 0 ? (num / den) * mult : null;
  const cacheRate = (s: ModelStats) => {
    const tot = s.input_tokens + s.cache_read_tokens + s.cache_create_tokens;
    return tot > 0 ? (s.cache_read_tokens / tot) * 100 : null;
  };
  const rows: { section: ComparisonRow["section"]; label: string; format: ComparisonRow["format"]; higherIsBetter: boolean; va: number | null; vb: number | null }[] = [
    { section: "Performance", label: "One-shot rate (%)",      format: "percent", higherIsBetter: true,  va: safe(a.one_shot_turns, a.edit_turns, 100), vb: safe(b.one_shot_turns, b.edit_turns, 100) },
    { section: "Performance", label: "Retry rate (/edit)",     format: "decimal", higherIsBetter: false, va: safe(a.retries, a.edit_turns), vb: safe(b.retries, b.edit_turns) },
    { section: "Efficiency",  label: "Cost / call ($)",        format: "cost",    higherIsBetter: false, va: safe(a.cost, a.calls), vb: safe(b.cost, b.calls) },
    { section: "Efficiency",  label: "Cost / edit ($)",        format: "cost",    higherIsBetter: false, va: safe(a.cost, a.edit_turns), vb: safe(b.cost, b.edit_turns) },
    { section: "Efficiency",  label: "Output tok / call",      format: "number",  higherIsBetter: false, va: safe(a.output_tokens, a.calls), vb: safe(b.output_tokens, b.calls) },
    { section: "Efficiency",  label: "Cache hit rate (%)",     format: "percent", higherIsBetter: true,  va: cacheRate(a), vb: cacheRate(b) },
    { section: "Efficiency",  label: "Edits / total turns (%)",format: "percent", higherIsBetter: true,  va: safe(a.edit_turns, a.total_turns, 100), vb: safe(b.edit_turns, b.total_turns, 100) },
  ];
  return rows.map(r => ({
    section: r.section, label: r.label, format: r.format, higherIsBetter: r.higherIsBetter,
    valueA: r.va, valueB: r.vb,
    winner: pickWinner(r.va, r.vb, r.higherIsBetter),
  }));
}
