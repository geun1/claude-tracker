-- Logical grouping of multiple sessions that belong to one task
-- (e.g. agent-team orchestrator + N parallel workers).
-- Sessions remain the unit of truth; groups are an overlay.
CREATE TABLE IF NOT EXISTS session_groups (
  id           TEXT PRIMARY KEY,
  name         TEXT,
  owner_email  TEXT NOT NULL,
  team         TEXT,
  created_at   TEXT NOT NULL,
  closed_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_groups_owner ON session_groups(owner_email);
CREATE INDEX IF NOT EXISTS idx_groups_created ON session_groups(created_at);

-- Members. A session can belong to one group at most (PK on session_id alone
-- would block re-attach; we PK on (group_id, session_id) so a session leaving
-- a group + joining another is allowed).
CREATE TABLE IF NOT EXISTS session_group_members (
  group_id   TEXT NOT NULL,
  session_id TEXT NOT NULL,
  role       TEXT,                  -- 'orchestrator' | 'worker' | NULL
  joined_at  TEXT NOT NULL,
  PRIMARY KEY (group_id, session_id)
);
CREATE INDEX IF NOT EXISTS idx_group_members_session ON session_group_members(session_id);
CREATE INDEX IF NOT EXISTS idx_group_members_group   ON session_group_members(group_id);

-- One Jira comment per (group, ticket) so re-running writeback can update.
CREATE TABLE IF NOT EXISTS group_ticket_comments (
  group_id        TEXT NOT NULL,
  ticket_key      TEXT NOT NULL,
  jira_comment_id TEXT NOT NULL,
  posted_at       TEXT NOT NULL,
  PRIMARY KEY (group_id, ticket_key)
);
