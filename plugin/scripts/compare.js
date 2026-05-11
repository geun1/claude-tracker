#!/usr/bin/env node
/**
 * /tracker-compare [modelA] [modelB] [days] — model side-by-side.
 *
 * No args: lists models by cost in the window.
 * With two model names (or substrings): prints 7 head-to-head metrics
 *   (one-shot rate, retry rate, cost/call, cost/edit, output tok/call,
 *   cache hit rate, edits/total).
 *
 * Inspired by codeburn `compare` (getagentseal/codeburn) — same metric set,
 * computed server-side from our events + messages.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");

function loadConfig() {
  const cands = [
    process.env.CLAUDE_TRACKER_CONFIG,
    path.join(os.homedir(), ".claude", "tracker.json"),
    path.join(os.homedir(), ".config", "claude-tracker", "config.json"),
  ].filter(Boolean);
  for (const p of cands) {
    try { if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf8")); } catch {}
  }
  return {};
}

async function get(pathName) {
  const cfg = loadConfig();
  const endpoint = cfg.endpoint || process.env.CLAUDE_TRACKER_ENDPOINT;
  const token = cfg.token || process.env.CLAUDE_TRACKER_TOKEN;
  if (!endpoint || !token) throw new Error("tracker.json에 endpoint/token 없음");
  const base = endpoint.replace(/\/events\/?$/, "").replace(/\/$/, "");
  const r = await fetch(base + pathName, { headers: { Authorization: `Bearer ${token}` } });
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}

function fmt(v, format) {
  if (v === null || v === undefined) return "—";
  if (format === "percent") return v.toFixed(1) + "%";
  if (format === "decimal") return v.toFixed(2);
  if (format === "cost")    return "$" + v.toFixed(4);
  if (format === "number")  return Math.round(v).toLocaleString();
  return String(v);
}

function shortModel(m) {
  return m.replace(/^.*\//, "").replace(/-\d{8}$/, "").slice(0, 28);
}

function pad(s, n) { return s.length >= n ? s : s + " ".repeat(n - s.length); }
function padL(s, n) { return s.length >= n ? s : " ".repeat(n - s.length) + s; }

function renderList(r) {
  const L = [];
  L.push("");
  L.push(`Models (최근 ${r.days}일, $ 내림차순):`);
  L.push("");
  L.push(`  ${pad("model", 32)}  ${padL("calls", 8)}  ${padL("cost", 10)}  ${padL("turns", 7)}  ${padL("edits", 6)}  ${padL("1-shot", 7)}  ${padL("retries", 8)}`);
  L.push("  " + "─".repeat(85));
  for (const m of r.models) {
    const oneShot = m.edit_turns > 0 ? (m.one_shot_turns / m.edit_turns * 100).toFixed(0) + "%" : "—";
    L.push(`  ${pad(shortModel(m.model), 32)}  ${padL(String(m.calls), 8)}  ${padL("$" + m.cost.toFixed(2), 10)}  ${padL(String(m.total_turns), 7)}  ${padL(String(m.edit_turns), 6)}  ${padL(oneShot, 7)}  ${padL(String(m.retries), 8)}`);
  }
  L.push("");
  L.push("👉 두 모델 비교: /tracker-compare <modelA> <modelB> [days]");
  return L.join("\n");
}

function renderComparison(r, c) {
  const L = [];
  const aName = shortModel(c.a.model);
  const bName = shortModel(c.b.model);
  L.push("");
  L.push(`📊 ${aName}  vs  ${bName}   (최근 ${r.days}일)`);
  L.push("");
  const w = (winner, side) => winner === side ? "✓" : winner === "tie" ? "=" : " ";
  let lastSection = "";
  for (const row of c.rows) {
    if (row.section !== lastSection) {
      L.push(`  ── ${row.section} ──`);
      lastSection = row.section;
    }
    const va = fmt(row.valueA, row.format);
    const vb = fmt(row.valueB, row.format);
    const aw = w(row.winner, "a");
    const bw = w(row.winner, "b");
    L.push(`    ${pad(row.label, 26)}  ${aw} ${padL(va, 12)}    ${bw} ${padL(vb, 12)}   ${row.higherIsBetter ? "↑" : "↓"}`);
  }
  L.push("");
  L.push(`  ${pad("",26)}    ${pad(aName, 14)}  ${pad(bName, 14)}`);
  return L.join("\n");
}

(async () => {
  const cfg = loadConfig();
  const email = cfg.user_email;
  if (!email) throw new Error("tracker.json에 user_email 없음");
  const args = process.argv.slice(2);
  // Detect numeric (days) vs string (model names)
  let modelA, modelB, days = 30;
  const numericArg = args.find(a => /^\d+$/.test(a));
  const stringArgs = args.filter(a => !/^\d+$/.test(a));
  if (numericArg) days = Math.min(90, Math.max(1, parseInt(numericArg, 10)));
  if (stringArgs.length >= 2) { modelA = stringArgs[0]; modelB = stringArgs[1]; }

  try {
    const qs = new URLSearchParams({ days: String(days) });
    if (modelA && modelB) { qs.set("modelA", modelA); qs.set("modelB", modelB); }
    const r = await get(`/api/users/${encodeURIComponent(email)}/compare?${qs}`);
    if (r.comparison) {
      console.log(renderComparison(r, r.comparison));
    } else {
      console.log(renderList(r));
      if (modelA || modelB) {
        console.log("");
        console.log(`(요청한 모델을 찾지 못함: A=${modelA || "?"}, B=${modelB || "?"})`);
      }
    }
  } catch (e) {
    console.error("error:", e.message || e);
    process.exit(1);
  }
})();
