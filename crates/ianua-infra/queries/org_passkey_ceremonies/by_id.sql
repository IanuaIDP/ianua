-- The passkey ceremony with the given id.
SELECT id, org_user_id, purpose, state, created_at, expires_at, consumed_at
FROM org_passkey_ceremonies
WHERE id = $1
