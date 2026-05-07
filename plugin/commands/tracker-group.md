---
description: Bundle multiple Claude Code sessions (e.g. agent-team workers across worktrees) into one logical task. Aggregated cost, ticket segments, and Jira writeback.
argument-hint: "<start|attach|status|list|ticket|end|done|close> [args]"
allowed-tools: Bash(node:*)
---

You are helping the user manage session groups on the duse-ai-plugin tracker. A group bundles 1 orchestrator session + N worker sessions (e.g. spawned in separate worktrees by /omc-teams or claude code teams) so that cost and ticket segments aggregate at the task level instead of being scattered across N session_ids.

Run: `node ${CLAUDE_PLUGIN_ROOT}/scripts/group.js $ARGUMENTS`

Subcommands:
- `start [name]` — create new group, attach current session as orchestrator, prints `export CLAUDE_TRACKER_GROUP_ID=...` for worker spawning.
- `attach <gid>` — attach current session to existing group as worker (manual fallback when env propagation isn't possible).
- `status [gid]` — show group details: members, tickets aggregation, writeback comments.
- `list` — list groups owned by the current user.
- `ticket <KEY> [gid]` — start ticket segment in *all* member sessions at once.
- `end [gid]` — close any open segments across the whole group.
- `done [gid]` — writeback: post one Jira comment per ticket combining all member sessions' work.
- `close [gid]` — close the group (no further attaches).

Worker auto-attach: if `CLAUDE_TRACKER_GROUP_ID` env var is set when a Claude Code session starts, the SessionStart hook auto-attaches that session to the group. So the orchestrator just exports the var before spawning workers; no per-worker setup needed. Group state also persists locally at `~/.claude/tracker-group-active` so subsequent slash commands without `[gid]` target the same group.

After the command runs:
- Echo the script's output as-is when it succeeds — already formatted.
- For `start`: emphasize the `export CLAUDE_TRACKER_GROUP_ID=...` line. The user must run that export *before* spawning workers (in tmux panes / Agent calls / etc.).
- For `done`: each line is a ticket — `✓` means Jira comment posted, `✗` means failed (commonly: no Jira connection — point to /tracker-jira set).
- If `error: 그룹 미지정` appears, suggest /tracker-group start or pass an explicit gid.
