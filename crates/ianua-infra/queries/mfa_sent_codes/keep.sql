-- Keeps a code as the latest sent for a user's second factor: a new code
-- replaces the one before it, and a known one takes its counted tries and
-- its spending.
INSERT INTO mfa_sent_codes
    (tenant_id, user_id, enrolled_at, method, code_hash, issued_at, expires_at,
     wrong_tries, spent_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (tenant_id, user_id) DO UPDATE SET
    enrolled_at = EXCLUDED.enrolled_at,
    method = EXCLUDED.method,
    code_hash = EXCLUDED.code_hash,
    issued_at = EXCLUDED.issued_at,
    expires_at = EXCLUDED.expires_at,
    wrong_tries = EXCLUDED.wrong_tries,
    spent_at = EXCLUDED.spent_at
