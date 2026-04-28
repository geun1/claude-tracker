#!/usr/bin/env node
/**
 * /tracker-config <endpoint> [token]
 *
 * Also accepts identity flags:
 *   --email=you@aptner.com  --name="송근일"  --team=AX  --department=Tech
 * Or env: CLAUDE_TRACKER_USER / CLAUDE_TRACKER_NAME / CLAUDE_TRACKER_TEAM / CLAUDE_TRACKER_DEPARTMENT
 */
const fs = require("fs");
const os = require("os");
const path = require("path");

const argv = process.argv.slice(2);
const positional = argv.filter((a) => !a.startsWith("--"));
const flags = Object.fromEntries(
  argv.filter((a) => a.startsWith("--")).map((a) => {
    const [k, ...v] = a.replace(/^--/, "").split("=");
    return [k, v.join("=") || true];
  })
);

const endpoint = positional[0];
const token = positional[1];

const file = path.join(os.homedir(), ".claude", "tracker.json");
fs.mkdirSync(path.dirname(file), { recursive: true });

let cfg = {};
try { cfg = JSON.parse(fs.readFileSync(file, "utf8")); } catch {}

if (endpoint) cfg.endpoint = endpoint;
if (token)    cfg.token = token;

const map = { email: "user_email", name: "user_name", team: "team", department: "department" };
for (const [flag, key] of Object.entries(map)) {
  if (flags[flag]) cfg[key] = flags[flag];
  else if (!cfg[key] && process.env[`CLAUDE_TRACKER_${flag.toUpperCase() === "EMAIL" ? "USER" : flag.toUpperCase()}`]) {
    cfg[key] = process.env[`CLAUDE_TRACKER_${flag.toUpperCase() === "EMAIL" ? "USER" : flag.toUpperCase()}`];
  }
}
cfg.local_log_dir = cfg.local_log_dir || path.join(os.homedir(), ".claude", "tracker-logs");

fs.writeFileSync(file, JSON.stringify(cfg, null, 2));

const masked = { ...cfg, token: cfg.token ? cfg.token.slice(0, 4) + "…" : null };
console.log("Wrote", file);
console.log(JSON.stringify(masked, null, 2));
const missing = [];
if (!cfg.user_email) missing.push("--email");
if (!cfg.team)       missing.push("--team");
if (missing.length) console.log(`\n⚠ 다음 정보를 추가하세요: ${missing.join(", ")}`);
