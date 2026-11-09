-- Keeps an OAuth client: a new one is added, a known one of the same tenant
-- takes the new values. Its tenant, public client id, who manages it and
-- its creation time never change.
INSERT INTO oauth_clients
    (id, tenant_id, client_id_value, credential, name, redirect_uris,
     post_logout_redirect_uris, grant_types, scopes, settings, registration_token_hash,
     admitted_with_id, status, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
ON CONFLICT (id) DO UPDATE SET
    credential = EXCLUDED.credential,
    name = EXCLUDED.name,
    redirect_uris = EXCLUDED.redirect_uris,
    post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
    grant_types = EXCLUDED.grant_types,
    scopes = EXCLUDED.scopes,
    settings = EXCLUDED.settings,
    status = EXCLUDED.status
WHERE oauth_clients.tenant_id = EXCLUDED.tenant_id
