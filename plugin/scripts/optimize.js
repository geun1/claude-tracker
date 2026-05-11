#!/usr/bin/env node
/**
 * /tracker-optimize [days] — server-side waste-pattern report.
 *
 * Calls GET /api/users/:email/optimize?days=N and pretty-prints:
 *   • Health grade (A-F) + score
 *   • Sessions scanned, total cost
 *   • Findings ranked by urgency, with token + dollar savings and the
 *     copy-paste-ready fix (destination labeled).
 *
 * Inspired by codeburn optimize (getagentseal/codeburn), but uses our
 * server-side data (events + messages on the tracker Worker) — no local
 * filesystem scan in this phase. Filesystem-dependent detectors
 * (Ghost agents, Unused MCP, Bloated CLAUDE.md, Bash Bloat) are Phase 2.
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

async function call(method, pathName) {
  const cfg = loadConfig();
  const endpoint = cfg.endpoint || process.env.CLAUDE_TRACKER_ENDPOINT;
  const token = cfg.token || process.env.CLAUDE_TRACKER_TOKEN;
  if (!endpoint || !token) throw new Error("tracker.json에 endpoint/token 없음 — /tracker-config 먼저");
  const base = endpoint.replace(/\/events\/?$/, "").replace(/\/$/, "");
  const r = await fetch(base + pathName, {
    method,
    headers: { Authorization: `Bearer ${token}` },
  });
  const text = await r.text();
  let j; try { j = JSON.parse(text); } catch { j = { _raw: text }; }
  if (!r.ok) throw new Error(j.error || j.detail || `HTTP ${r.status}`);
  return j;
}

function gradeColor(grade) {
  return { A: "🟢", B: "🟢", C: "🟡", D: "🟠", F: "🔴" }[grade] || "⚪";
}

function impactBadge(impact) {
  return { high: "🔴 HIGH  ", medium: "🟡 MEDIUM", low: "🟢 LOW   " }[impact] || impact;
}

function fmtNum(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "K";
  return String(n);
}

function destLabel(d) {
  return {
    "claude-md": "→ CLAUDE.md 에 추가 (영구 룰)",
    "session-opener": "→ 다음 세션 시작 시 붙여넣기",
    "prompt": "→ 지금 Claude에게 요청",
    "command": "→ 쉘에서 실행",
    "shell-config": "→ ~/.zshrc 또는 ~/.bashrc 에 추가",
    "info": "→ 참고 정보",
  }[d] || d;
}

function render(report) {
  const L = [];
  L.push("");
  L.push(`${gradeColor(report.grade)} 설정 건강도: ${report.grade}  (점수 ${report.score}/100)`);
  L.push(`   범위: 최근 ${report.days}일 · ${report.sessions_scanned}개 세션 · $${report.total_cost_usd.toFixed(2)} · ${fmtNum(report.total_tokens)} tok`);
  L.push("");

  if (report.findings.length === 0) {
    L.push("✓ 발견된 낭비 패턴 없음. 건강하게 사용 중입니다.");
    L.push("");
    return L.join("\n");
  }

  // Category breakdown summary
  const cb = report.category_breakdown || {};
  const cats = Object.entries(cb).map(([k, v]) => ({ cat: k, ...v })).sort((a, b) => b.cost - a.cost).slice(0, 6);
  if (cats.length) {
    L.push(`📊 작업 카테고리 (top ${cats.length}):`);
    for (const c of cats) {
      const oneShotPct = c.edit_turns > 0 ? Math.round(c.one_shot_turns / c.edit_turns * 100) : null;
      const oneShot = oneShotPct === null ? "" : `  one-shot ${oneShotPct}%`;
      L.push(`   ${c.cat.padEnd(14)} turns=${String(c.turns).padStart(4)}  $${c.cost.toFixed(2).padStart(7)}  retries=${c.retries}${oneShot}`);
    }
    L.push("");
  }

  L.push(`발견 (${report.findings.length}개, 긴급도순):`);
  L.push("");
  for (const f of report.findings) {
    L.push(`${impactBadge(f.impact)}  ${f.title}`);
    L.push(`   ${f.detail}`);
    L.push(`   절약 예상: ${fmtNum(f.tokensSaved)} 토큰 · ~$${f.usdSaved.toFixed(2)}`);
    L.push(`   ${destLabel(f.fix.destination)}`);
    L.push("");
    for (const ln of f.fix.content.split("\n")) L.push("     " + ln);
    L.push("");
    L.push("   " + "─".repeat(60));
    L.push("");
  }
  return L.join("\n");
}

(async () => {
  const cfg = loadConfig();
  const email = cfg.user_email;
  if (!email) throw new Error("tracker.json에 user_email 없음");
  const days = parseInt(process.argv[2] || "30", 10);
  if (isNaN(days) || days < 1 || days > 90) throw new Error("days는 1~90 사이여야 함");
  try {
    const r = await call("GET", `/api/users/${encodeURIComponent(email)}/optimize?days=${days}`);
    console.log(render(r));
  } catch (e) {
    console.error("error:", e.message || e);
    process.exit(1);
  }
})();
