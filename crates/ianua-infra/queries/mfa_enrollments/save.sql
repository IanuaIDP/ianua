-- Keeps a user's second factor: a new one is added, a known one takes the
-- new values. Its tenant and user never change, and neither does the
-- latest code step accepted, which only claiming a step moves.
INSERT INTO mfa_enrollments
    (tenant_id, user_id, method, sealed_secret, phone_number, status, verified_at,
     recovery_codes_hash, disabled_at, failed_attempts, last_failed_at, enrolled_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (tenant_id, user_id) DO UPDATE SET
    method = EXCLUDED.method,
    sealed_secret = EXCLUDED.sealed_secret,
    phone_number = EXCLUDED.phone_number,
    status = EXCLUDED.status,
    verified_at = EXCLUDED.verified_at,
    recovery_codes_hash = EXCLUDED.recovery_codes_hash,
    disabled_at = EXCLUDED.disabled_at,
    failed_attempts = EXCLUDED.failed_attempts,
    last_failed_at = EXCLUDED.last_failed_at,
    enrolled_at = EXCLUDED.enrolled_at
