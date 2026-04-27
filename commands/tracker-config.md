---
description: Configure the claude-tracker endpoint, token, and user email.
argument-hint: "<endpoint> [token]"
allowed-tools: Bash(node:*)
---

Set tracker config. Writes to `~/.claude/tracker.json`.

Run: `node ${CLAUDE_PLUGIN_ROOT}/scripts/configure.js "$1" "$2"`

After writing, print the new sanitized config (token masked).
