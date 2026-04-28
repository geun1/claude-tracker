#!/usr/bin/env node
/**
 * First-run bootstrap. Runs on every SessionStart but is cheap and idempotent.
 * If user/team/email are missing, prints a one-time stderr nudge so the user
 * knows how to identify themselves. Also pulls company defaults from env.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");

const CFG = path.join(os.homedir(), ".claude", "tracker.json");
const STAMP = path.join(os.homedir(), ".claude", ".tracker-bootstrapped");

function load() { try { return JSON.parse(fs.readFileSync(CFG, "utf8")); } catch { return {}; } }
function save(c) { fs.mkdirSync(path.dirname(CFG), { recursive: true }); fs.writeFileSync(CFG, JSON.stringify(c, null, 2)); }

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

// One-time nudge if identity is incomplete
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

process.exit(0);
