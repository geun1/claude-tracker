-- Add role-based access: admin / manager / general (default)
ALTER TABLE tokens ADD COLUMN role TEXT NOT NULL DEFAULT 'general';

-- Backfill: existing is_admin=1 → admin, otherwise general
UPDATE tokens SET role = 'admin' WHERE is_admin = 1;
UPDATE tokens SET role = 'general' WHERE is_admin = 0;

CREATE INDEX IF NOT EXISTS idx_tokens_role ON tokens(role);
