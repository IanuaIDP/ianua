-- Keeps a dashboard sign-in waiting on the organization's provider, under a
-- digest of its key. A request kept again under the same key replaces the
-- one before.
INSERT INTO org_sso_requests
    (key_kind, key_hash, organization_id, connection_id, binding_hash,
     tenant_slug, nonce, pkce_verifier, redirect_uri, lapses_at)
VALUES ($1, sha256(convert_to($2, 'UTF8')), $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (key_kind, key_hash) DO UPDATE SET
    organization_id = EXCLUDED.organization_id,
    connection_id = EXCLUDED.connection_id,
    binding_hash = EXCLUDED.binding_hash,
    tenant_slug = EXCLUDED.tenant_slug,
    nonce = EXCLUDED.nonce,
    pkce_verifier = EXCLUDED.pkce_verifier,
    redirect_uri = EXCLUDED.redirect_uri,
    lapses_at = EXCLUDED.lapses_at
