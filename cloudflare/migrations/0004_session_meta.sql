-- 세션별 커스텀 이름 (기본은 첫 사용자 메시지 / 세션 ID)
CREATE TABLE IF NOT EXISTS sessions_meta (
  session_id TEXT PRIMARY KEY,
  name TEXT,
  updated_by TEXT,
  updated_at TEXT
);
