-- Keeps an OIDC sign-in of a tenant waiting on its provider, under a
-- digest of its state. A sign-in kept again under the same state replaces
-- the one before.
INSERT INTO oidc_flows
    (tenant_id, state_hash, connection_id, nonce, sealed_pkce_verifier, redirect_uri,
     binding_hash, dashboard_hash, lapses_at)
VALUES ($1, sha256(convert_to($2, 'UTF8')), $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (tenant_id, state_hash) DO UPDATE SET
    connection_id = EXCLUDED.connection_id,
    nonce = EXCLUDED.nonce,
    sealed_pkce_verifier = EXCLUDED.sealed_pkce_verifier,
    redirect_uri = EXCLUDED.redirect_uri,
    binding_hash = EXCLUDED.binding_hash,
    dashboard_hash = EXCLUDED.dashboard_hash,
    lapses_at = EXCLUDED.lapses_at
