-- The passkey with the given WebAuthn credential id, whoever holds it.
SELECT id, org_user_id, credential_id, public_key, sign_count,
       authenticator_type, attestation, name, last_used_at, created_at
FROM org_passkey_credentials
WHERE credential_id = $1
