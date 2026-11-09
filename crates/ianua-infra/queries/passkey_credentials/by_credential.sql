-- The passkey of a tenant with the given WebAuthn credential id.
SELECT id, user_id, credential_id, public_key, sign_count,
       authenticator_type, attestation, name, last_used_at, created_at
FROM passkey_credentials
WHERE tenant_id = $1 AND credential_id = $2
