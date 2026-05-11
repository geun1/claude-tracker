-- 세션 품질 신호: LLM 비사용. tool_calls_json 패턴 매칭만으로 추출.
--
-- session_analysis가 'Gemini 분석 결과(티켓·요약)'을 담는다면, session_quality는
-- 'LLM 없이 측정 가능한 위험 신호'를 담는다. 회계 단위가 다르므로 분리.
-- 향후 process/decision quality는 같은 테이블에 컬럼 추가하거나 별 테이블로 확장.

CREATE TABLE IF NOT EXISTS session_quality (
  session_id TEXT PRIMARY KEY,
  user_email TEXT,                                  -- denormalized for admin filtering
  team TEXT,
  scanned_at TEXT NOT NULL,
  scanner_version INTEGER NOT NULL DEFAULT 1,

  -- Risk signals: counts (0 = clean). 카운트로 둬서 1회/N회 빈도 차이를 보존.
  risk_no_verify INTEGER NOT NULL DEFAULT 0,        -- --no-verify, --no-gpg-sign, --no-edit
  risk_force INTEGER NOT NULL DEFAULT 0,            -- git push/reset --force
  risk_reset_hard INTEGER NOT NULL DEFAULT 0,       -- git reset --hard, git checkout .
  risk_destructive_rm INTEGER NOT NULL DEFAULT 0,   -- rm -rf
  risk_drop_sql INTEGER NOT NULL DEFAULT 0,         -- DROP TABLE/DATABASE/SCHEMA, TRUNCATE
  risk_total INTEGER NOT NULL DEFAULT 0,            -- sum of all risk_* (denormalized for fast filter)

  -- Volume signals (denominators for "rate" calc)
  message_count INTEGER NOT NULL DEFAULT 0,
  bash_call_count INTEGER NOT NULL DEFAULT 0,
  tool_call_count INTEGER NOT NULL DEFAULT 0,

  -- Sample evidence: JSON [{kind, seq, snippet}] capped at 10 items
  evidence_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_squality_user_scanned ON session_quality(user_email, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_squality_team_scanned ON session_quality(team, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_squality_risk         ON session_quality(risk_total DESC, scanned_at DESC);
