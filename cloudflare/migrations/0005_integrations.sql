-- 사용자별 외부 통합 (Jira 등). API 토큰은 AES-GCM으로 암호화해 저장.
CREATE TABLE IF NOT EXISTS user_integrations (
  user_email TEXT NOT NULL,
  kind TEXT NOT NULL,                  -- 'jira' | 'github' | ...
  base_url TEXT,                       -- e.g. https://aptner.atlassian.net
  account_email TEXT,                  -- jira 계정 이메일 (basic auth용)
  token_iv TEXT,                       -- base64 IV (AES-GCM)
  token_ct TEXT,                       -- base64 ciphertext + tag
  meta_json TEXT,                      -- 응답 메타 (프로젝트 수 등)
  created_at TEXT,
  updated_at TEXT,
  PRIMARY KEY (user_email, kind)
);

-- LLM이 추론한 세션 분석 결과 (사용자가 "분석" 버튼 누른 결과 캐시)
CREATE TABLE IF NOT EXISTS session_analysis (
  session_id TEXT PRIMARY KEY,
  ticket_key TEXT,
  ticket_confidence REAL,
  summary TEXT,
  category TEXT,                       -- feature|bugfix|refactor|docs|chore|exploration
  key_changes TEXT,                    -- JSON array
  model TEXT,                          -- 분석에 쓴 모델 (claude-haiku-4-5)
  cost_usd REAL,
  analyzed_by TEXT,                    -- actor email
  analyzed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_analysis_ticket ON session_analysis(ticket_key);

-- Jira 티켓 메타 캐시 (10분 TTL)
CREATE TABLE IF NOT EXISTS jira_tickets (
  key TEXT NOT NULL,
  user_email TEXT NOT NULL,            -- 누구의 jira 토큰으로 조회됐는지
  summary TEXT,
  status TEXT,
  assignee_email TEXT,
  url TEXT,
  fetched_at TEXT,
  PRIMARY KEY (key, user_email)
);

-- 세션의 git 컨텍스트 (hook이 Stop 시 push)
CREATE TABLE IF NOT EXISTS session_git (
  session_id TEXT PRIMARY KEY,
  repo_root TEXT,
  remote_url TEXT,
  branch TEXT,
  commits_json TEXT,                   -- [{sha, msg, ts}]
  diff_stat TEXT,                      -- "12 files, +247 -38"
  collected_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_git_branch ON session_git(branch);
