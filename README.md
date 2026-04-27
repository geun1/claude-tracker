# claude-tracker

A Claude Code plugin that records every session's history, usage, tokens, model, and config to a remote server (and a local JSONL fallback). Inspired by [claude-code-history-viewer](https://github.com/jhlee0409/claude-code-history-viewer) — but built as a first-class Claude Code plugin with hooks, not a post-hoc log reader.

## What it captures

Per hook event (`SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`, `Notification`, `SessionEnd`):

- `session_id`, `cwd`, `event`, timestamp
- user: email (from config), `os.userInfo().username`, hostname, platform
- model (parsed from the transcript's latest assistant turn)
- token usage: `input_tokens`, `output_tokens`, `cache_read_input_tokens`, `cache_creation_input_tokens`
- tool name + raw hook payload
- a lightweight config snapshot (permission mode, etc.)

Hooks read the transcript path provided by Claude Code and tail the last ~25 JSONL lines to extract the newest `usage` block — that's the canonical source of token counts.

## Install

This is a local plugin. Add it to Claude Code via a marketplace entry pointing at this directory, or symlink into a marketplace you already use. Directory layout follows the standard:

```
claude-tracker/
├── .claude-plugin/plugin.json
├── hooks/hooks.json
├── commands/
│   ├── tracker-stats.md
│   └── tracker-config.md
└── scripts/
    ├── hook.js
    ├── stats.js
    └── configure.js
```

## Configure

Create `~/.claude/tracker.json`:

```json
{
  "endpoint": "http://localhost:3737/events",
  "token": "optional-bearer-token",
  "user_email": "gsong@aptner.com",
  "local_log_dir": "~/.claude/tracker-logs"
}
```

Or use the slash command:

```
/tracker-config http://localhost:3737/events my-token
```

Env overrides: `CLAUDE_TRACKER_ENDPOINT`, `CLAUDE_TRACKER_TOKEN`, `CLAUDE_TRACKER_USER`, `CLAUDE_TRACKER_CONFIG`.

If `endpoint` is unset, events are still written to `~/.claude/tracker-logs/YYYY-MM-DD.jsonl` so nothing is lost.

## Run the server

```bash
cd claude-tracker/server
npm install
PORT=3737 TRACKER_TOKEN=my-token npm start
```

Endpoints:

| Method | Path            | Purpose                                    |
|--------|-----------------|--------------------------------------------|
| POST   | `/events`       | Ingest hook events                         |
| GET    | `/stats?days=7` | Aggregated totals, by-model, by-tool, by-user |
| GET    | `/sessions`     | Recent session summaries                   |
| GET    | `/events`       | Raw events (filter `?session_id=`)         |
| GET    | `/health`       | Health check                               |

Storage is SQLite (`better-sqlite3`) at `./tracker.db` by default.

## View stats

```
/tracker-stats 14
```

Prints local-log aggregates and, if the server is reachable, its `/stats` response too.

## Design notes

- Hooks **never block** the session — every hook exits 0 even on failure, and network posts have a 2s timeout.
- Token accounting uses the transcript's `usage` block (matches what Claude Code itself reports).
- No prompt or tool-output content is stored by default beyond the raw hook payload. Strip `payload_json` on the server side if you need tighter PII hygiene.
- The server is intentionally minimal; point multiple machines at one instance to get a team-wide usage dashboard.
