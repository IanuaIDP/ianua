-- Keeps an impersonation grant: a new one is added, a known one takes its
-- revocation. Who it lets act as whom, why and for how long never change.
-- A revoked grant takes nothing new, so a save of a copy read before the
-- revocation never makes it live again or moves the time it was revoked.
INSERT INTO impersonation_grants
    (id, operator_id, tenant_id, user_id, reason, expires_at, revoked_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
    revoked_at = EXCLUDED.revoked_at
WHERE impersonation_grants.operator_id = EXCLUDED.operator_id
    AND impersonation_grants.revoked_at IS NULL
