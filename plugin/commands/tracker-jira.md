---
description: Manage Jira credentials on the tracker Worker. Saved server-side (encrypted) and shared across every Claude session that uses the same tracker token.
argument-hint: "<status|set|test|disconnect> [--url=...] [--email=...] [--token=...]"
allowed-tools: Bash(node:*)
---

You are helping the user manage their Jira credentials on the duse-ai-plugin tracker Worker.

Run: `node ${CLAUDE_PLUGIN_ROOT}/scripts/jira.js $ARGUMENTS`

Subcommands:
- `status` — show whether Jira is connected and account info.
- `set --url=URL --email=E --token=T` — save credentials. Worker validates them against `/rest/api/3/myself` and rejects bad ones; only verified credentials are stored (encrypted at rest with `INTEGRATION_KEY`).
- `test --url=URL --email=E --token=T` — test specific credentials without saving.
- `test` — re-test currently saved credentials.
- `disconnect` — delete saved credentials from the Worker.

Once saved, the credentials are reused automatically by every Claude session authenticated with the same tracker user-token — no per-session setup needed.

⚠ The token is captured in the slash-command transcript when passed inline. If that's a concern, run `node ${CLAUDE_PLUGIN_ROOT}/scripts/jira.js set --url=... --email=... --token=...` directly in your terminal instead of through the slash command.

After the command runs:
- Echo the script's output as-is when it succeeds — it's already formatted for the user.
- If `error: tracker.json에 endpoint/token 없음` appears, tell the user to run `/tracker-config` first.
- If `set` fails with `jira auth failed`, the URL/email/token combination is wrong — most often a typo in the email or an expired API token.
