-- The passkeys a user of a tenant registered, in the order they were
-- added.
SELECT id, user_id, credential_id, public_key, sign_count,
       authenticator_type, attestation, name, last_used_at, created_at
FROM passkey_credentials
WHERE tenant_id = $1 AND user_id = $2
ORDER BY created_at, id
