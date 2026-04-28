-- 사용자가 직접 등록한 Claude 플랜 (자기 신고)
-- 추론된 권장 플랜과 별도로, 본인이 가입한 플랜을 표시/집계용으로 저장.
ALTER TABLE tokens ADD COLUMN plan TEXT;          -- 'pro' | 'max-5x' | 'max-20x' | 'team' | 'api' | NULL
ALTER TABLE tokens ADD COLUMN plan_updated_at TEXT;
