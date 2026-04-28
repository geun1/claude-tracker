---
description: Show recent Claude Code usage stats from the tracker server or local logs.
argument-hint: "[days]"
allowed-tools: Bash(node:*), Bash(curl:*), Bash(cat:*)
---

Query tracker usage for the last ${1:-7} days.

Run: `node ${CLAUDE_PLUGIN_ROOT}/scripts/stats.js ${1:-7}`

Summarize token totals by model, session count, top tools used, and cwd breakdown.
