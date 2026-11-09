-- The impersonation grants with the given ids, in whichever tenant.
SELECT id, operator_id, tenant_id, user_id, reason, expires_at, revoked_at, created_at
FROM impersonation_grants
WHERE id = ANY($1)
