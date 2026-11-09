-- The passkeys an organization member registered, in the order they were
-- added.
SELECT id, org_user_id, credential_id, public_key, sign_count,
       authenticator_type, attestation, name, last_used_at, created_at
FROM org_passkey_credentials
WHERE org_user_id = $1
ORDER BY created_at, id
