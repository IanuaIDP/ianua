-- The passkey ceremony of a tenant with the given id.
SELECT id, tenant_id, user_id, purpose, state, created_at, expires_at, consumed_at
FROM passkey_ceremonies
WHERE tenant_id = $1 AND id = $2
