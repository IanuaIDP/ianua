-- Keeps a link: a new one is added, a known one keeps when it was used.
-- Whom it is for, where it went and when it runs out never change.
INSERT INTO mailed_links
    (tenant_id, purpose, token_hash, user_id, sent_to, created_at, expires_at, used_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (tenant_id, purpose, token_hash) DO UPDATE SET
    used_at = EXCLUDED.used_at
