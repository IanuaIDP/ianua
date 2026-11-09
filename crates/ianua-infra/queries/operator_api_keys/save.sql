-- Keeps an operator API key: a new one is added, a known one takes its
-- revocation. Its operator, hash, expiry and creation time never change.
-- A revoked key takes nothing new, so a save of a copy read before the
-- revocation never makes it work again or moves the time it was revoked.
INSERT INTO operator_api_keys (key_prefix, operator_id, key_hash, expires_at, revoked_at,
                               created_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (key_prefix) DO UPDATE SET
    revoked_at = EXCLUDED.revoked_at
WHERE operator_api_keys.operator_id = EXCLUDED.operator_id
    AND operator_api_keys.revoked_at IS NULL
