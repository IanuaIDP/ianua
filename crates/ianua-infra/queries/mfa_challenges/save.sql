-- Keeps a second-factor challenge: a new one is added, a known one of the
-- same tenant counts one more wrong code on what is stored, at least the
-- count it brings, so two wrong codes saved from copies read together both
-- count. Its session and expiry never change, and an answer is never
-- undone.
INSERT INTO mfa_challenges
    (tenant_id, token_hash, session_id, expires_at, failed_attempts, consumed_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_id, token_hash) DO UPDATE SET
    failed_attempts = GREATEST(mfa_challenges.failed_attempts + 1, EXCLUDED.failed_attempts),
    consumed_at = coalesce(mfa_challenges.consumed_at, EXCLUDED.consumed_at)
