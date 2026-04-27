-- claude-tracker D1 schema
-- D1 is SQLite-compatible; this mirrors server/server.js but adapted for the edge.

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  event TEXT NOT NULL,
  session_id TEXT,
  user_email TEXT,
  user_name TEXT,
  team TEXT,
  department TEXT,
  host TEXT,
  platform TEXT,
  cwd TEXT,
  model TEXT,
  input_tokens INTEGER DEFAULT 0,
  output_tokens INTEGER DEFAULT 0,
  cache_read_tokens INTEGER DEFAULT 0,
  cache_create_tokens INTEGER DEFAULT 0,
  tool_name TEXT,
  client_ip TEXT,
  client_city TEXT,
  client_country TEXT,
  user_agent TEXT,
  payload_json TEXT,         -- small payloads only; large ones go to R2
  payload_r2_key TEXT        -- R2 object key when payload > 50KB
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_email);
CREATE INDEX IF NOT EXISTS idx_events_team ON events(team);
CREATE INDEX IF NOT EXISTS idx_events_user_ts ON events(user_email, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_session_ts ON events(session_id, ts);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  ts TEXT NOT NULL,
  role TEXT NOT NULL,
  user_email TEXT,
  team TEXT,
  cwd TEXT,
  model TEXT,
  text TEXT,                -- inlined when small
  thinking TEXT,
  tool_calls_json TEXT,
  tool_result_json TEXT,
  text_r2_key TEXT,         -- R2 fallback for huge text
  result_r2_key TEXT,       -- R2 fallback for huge tool outputs
  input_tokens INTEGER DEFAULT 0,
  output_tokens INTEGER DEFAULT 0,
  cache_read_tokens INTEGER DEFAULT 0,
  cache_create_tokens INTEGER DEFAULT 0,
  UNIQUE(session_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_msg_session ON messages(session_id, seq);
CREATE INDEX IF NOT EXISTS idx_msg_user ON messages(user_email);
CREATE INDEX IF NOT EXISTS idx_msg_ts ON messages(ts);

-- Audit log: who looked at whose data
CREATE TABLE IF NOT EXISTS access_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor_email TEXT NOT NULL,    -- from CF-Access-Authenticated-User-Email
  action TEXT NOT NULL,         -- 'view_session' | 'view_user' | 'export_csv' | ...
  target_user TEXT,
  target_session TEXT,
  ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON access_log(actor_email, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_target ON access_log(target_user, ts DESC);

-- Retention bookkeeping (daily cron writes here)
CREATE TABLE IF NOT EXISTS retention_runs (
  ts TEXT PRIMARY KEY,
  events_purged INTEGER DEFAULT 0,
  messages_purged INTEGER DEFAULT 0,
  r2_objects_purged INTEGER DEFAULT 0,
  notes TEXT
);
