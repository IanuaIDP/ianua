-- Keeps a member's passkey: a new one is added, a known one of the same
-- member and organization takes its new name, counter and last use. Its
-- member, organization, credential id, public key and registration time
-- never change. The counter and the last use only move forward, so a save
-- of a copy read before a later sign-in never lowers the counter a cloned
-- key is caught by.
INSERT INTO org_passkey_credentials
    (id, organization_id, org_user_id, credential_id, public_key, sign_count,
     authenticator_type, attestation, name, last_used_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (id) DO UPDATE SET
    sign_count = GREATEST(org_passkey_credentials.sign_count, EXCLUDED.sign_count),
    name = EXCLUDED.name,
    last_used_at = GREATEST(org_passkey_credentials.last_used_at, EXCLUDED.last_used_at)
WHERE org_passkey_credentials.organization_id = EXCLUDED.organization_id
    AND org_passkey_credentials.org_user_id = EXCLUDED.org_user_id
