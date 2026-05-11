---
description: Detect Claude Code usage waste patterns (junk reads, duplicate reads, low read/edit ratio, cache bloat, low-worth sessions, context bloat, session outliers). A-F config health grade. Inspired by codeburn.
argument-hint: "[days]"
allowed-tools: Bash(node:*)
---

You are helping the user audit their recent Claude Code sessions for waste patterns. The server scans events + messages for the user's last N days (default 30, max 90) and returns ranked findings with token + dollar savings estimates and copy-paste-ready fixes.

Run: `node ${CLAUDE_PLUGIN_ROOT}/scripts/optimize.js $ARGUMENTS`

After the command runs:
- Echo the script's output as-is — it's pre-formatted.
- Each finding has a destination label (CLAUDE.md / session-opener / shell-config / prompt / info). Help the user apply the most impactful (HIGH) ones first.
- If the user asks "왜 이렇게 점수가 낮아?" / "이거 어떻게 고쳐?", refer to the specific finding shown and explain the mechanism (e.g. "node_modules 같은 정크 디렉토리를 Read 하면 토큰만 잡아먹고 가치는 없다 — 그래서 CLAUDE.md에 회피 룰 추가").
- Filesystem-dependent rules (CLAUDE.md bloat, ghost agents/skills/commands, unused MCP, BASH_MAX_OUTPUT_LENGTH) are NOT included in this phase — they need a client-side hook scan (planned).
