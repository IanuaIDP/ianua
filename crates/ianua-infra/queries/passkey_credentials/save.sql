-- Keeps a user's passkey: a new one is added, a known one of the same
-- tenant and user takes its new name, counter and last use. Its credential
-- id, public key and registration time never change. The counter and the
-- last use only move forward, so a save of a copy read before a later
-- sign-in never lowers the counter a cloned key is caught by.
INSERT INTO passkey_credentials
    (id, tenant_id, user_id, credential_id, public_key, sign_count,
     authenticator_type, attestation, name, last_used_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (id) DO UPDATE SET
    sign_count = GREATEST(passkey_credentials.sign_count, EXCLUDED.sign_count),
    name = EXCLUDED.name,
    last_used_at = GREATEST(passkey_credentials.last_used_at, EXCLUDED.last_used_at)
WHERE passkey_credentials.tenant_id = EXCLUDED.tenant_id
    AND passkey_credentials.user_id = EXCLUDED.user_id
