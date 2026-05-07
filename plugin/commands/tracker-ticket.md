---
description: Link this Claude Code session to a Jira ticket and pull its context. Subcommands - start KEY, end, context KEY, list, done.
argument-hint: "<start|end|context|list|done|wiki> [KEY]"
allowed-tools: Bash(node:*)
---

You are helping the user link the current Claude Code session to a Jira ticket via the duse-ai-plugin tracker.

Run: `node ${CLAUDE_PLUGIN_ROOT}/scripts/ticket.js $ARGUMENTS`

After the command runs:

- For `start KEY`: a Jira ticket context block was printed. Treat the ticket's description, recent comments, and linked issues as PRIMARY context for this session — incorporate them when planning code changes. The user is now actively working on this ticket; their subsequent requests should be interpreted in this scope.
- For `context KEY`: a read-only ticket context lookup. Summarize and use as background.
- For `end`: the user paused/finished the current ticket segment. Note this in your own state.
- For `list`: shows the segments timeline for this session (one ticket can have multiple segments if user switched back and forth).
- For `done`: writeback complete — summaries posted to Jira as comments. Acknowledge briefly.

Do NOT re-explain command output the user can already read; respond concisely. If `error: CLAUDE_SESSION_ID not set` appears, tell the user the tracker plugin SessionStart hook didn't run.
