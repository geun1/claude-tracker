-- Auto-grouping by (user, repo). After /tracker-ticket start KEY, the orchestrator's
-- session creates a group keyed on the git remote_url. Sub-sessions starting in the
-- same repo (any worktree thereof) auto-attach via /api/sessions/recommendations.
ALTER TABLE session_groups ADD COLUMN repo_remote       TEXT;
ALTER TABLE session_groups ADD COLUMN repo_root         TEXT;
ALTER TABLE session_groups ADD COLUMN active_ticket_key TEXT;
ALTER TABLE session_groups ADD COLUMN last_activity_at  TEXT;

CREATE INDEX IF NOT EXISTS idx_groups_active_lookup
  ON session_groups(owner_email, repo_remote, closed_at);
CREATE INDEX IF NOT EXISTS idx_groups_active_root
  ON session_groups(owner_email, repo_root, closed_at);
