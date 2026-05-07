#!/usr/bin/env node
/**
 * First-run bootstrap. Runs on every SessionStart but is cheap and idempotent.
 *
 *   1. Pulls company-wide defaults from env into ~/.claude/tracker.json.
 *   2. Prints a one-time stderr nudge if email/team are missing.
 *   3. Prints a one-time stderr nudge if Jira integration is not connected
 *      on the Worker (a separate stamp from #2 — Jira is optional but useful).
 */
const fs = require("fs");
const os = require("os");
const path = require("path");

const CFG = path.join(os.homedir(), ".claude", "tracker.json");
const STAMP = path.join(os.homedir(), ".claude", ".tracker-bootstrapped");
const JIRA_STAMP = path.join(os.homedir(), ".claude", ".tracker-jira-nudged");

function load() { try { return JSON.parse(fs.readFileSync(CFG, "utf8")); } catch { return {}; } }
function save(c) { fs.mkdirSync(path.dirname(CFG), { recursive: true }); fs.writeFileSync(CFG, JSON.stringify(c, null, 2)); }

async function checkJira(cfg) {
  // Only meaningful once tracker auth is configured.
  if (!cfg.endpoint || !cfg.token) return;
  if (fs.existsSync(JIRA_STAMP)) return;
  const base = cfg.endpoint.replace(/\/events\/?$/, "").replace(/\/$/, "");
  let hasJira = null;
  try {
    const res = await fetch(base + "/api/integrations", {
      headers: { Authorization: `Bearer ${cfg.token}` },
      signal: AbortSignal.timeout(2500),
    });
    if (!res.ok) return; // auth or server problem — don't nudge, don't stamp
    const list = await res.json();
    hasJira = Array.isArray(list) && list.some((x) => x?.kind === "jira");
  } catch { return; } // network / timeout — try again next session

  if (!hasJira) {
    process.stderr.write(
      "\n[claude-tracker] Jira 미연결 — 세션을 티켓에 매칭하고 작업 요약을 자동 댓글로 남기려면:\n" +
      "  /tracker-jira set --url=https://your.atlassian.net --email=you@x.com --token=ATATT...\n" +
      "  (Jira API 토큰 발급: https://id.atlassian.com/manage-profile/security/api-tokens)\n" +
      "  필요 없으면 무시하세요. 이 안내는 한 번만 보입니다.\n\n"
    );
  }
  try { fs.writeFileSync(JIRA_STAMP, new Date().toISOString()); } catch {}
}

(async () => {
  const cfg = load();
  let changed = false;

  // Pull company-wide defaults from env (typical: set in /etc/profile or ~/.zshrc)
  const envMap = {
    endpoint:   "CLAUDE_TRACKER_ENDPOINT",
    token:      "CLAUDE_TRACKER_TOKEN",
    user_email: "CLAUDE_TRACKER_USER",
    user_name:  "CLAUDE_TRACKER_NAME",
    team:       "CLAUDE_TRACKER_TEAM",
    department: "CLAUDE_TRACKER_DEPARTMENT",
  };
  for (const [k, env] of Object.entries(envMap)) {
    if (!cfg[k] && process.env[env]) { cfg[k] = process.env[env]; changed = true; }
  }
  if (changed) save(cfg);

  // One-time identity nudge if email/team incomplete
  if (!fs.existsSync(STAMP)) {
    const missing = [];
    if (!cfg.user_email || cfg.user_email === os.userInfo().username) missing.push("이메일");
    if (!cfg.team)                                                    missing.push("팀");
    if (missing.length) {
      process.stderr.write(
        `\n[claude-tracker] 사용자 식별 정보 미설정: ${missing.join(", ")}\n` +
        `  실행: /tracker-config <endpoint> <token>  (또는)\n` +
        `         echo '{"user_email":"you@aptner.com","team":"AX","user_name":"송근일"}' > ~/.claude/tracker.json\n\n`
      );
    }
    try { fs.writeFileSync(STAMP, new Date().toISOString()); } catch {}
  }

  // One-time Jira nudge — separate stamp from identity so users can be nudged
  // even if their identity was already set up before this feature shipped.
  await checkJira(cfg);

  process.exit(0);
})();
