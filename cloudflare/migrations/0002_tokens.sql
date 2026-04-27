-- Per-user API tokens. We store only the sha256 hash; raw token shown once at issuance.
CREATE TABLE IF NOT EXISTS tokens (
  token_hash TEXT PRIMARY KEY,
  user_email TEXT NOT NULL,
  user_name TEXT,
  team TEXT,
  is_admin INTEGER DEFAULT 0,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT,
  notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_email);
CREATE INDEX IF NOT EXISTS idx_tokens_active ON tokens(revoked_at) WHERE revoked_at IS NULL;
