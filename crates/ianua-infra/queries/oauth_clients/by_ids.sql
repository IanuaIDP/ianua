-- The OAuth clients of one tenant with the given ids.
SELECT id, client_id_value, credential, name, redirect_uris, post_logout_redirect_uris,
       grant_types, scopes, settings, registration_token_hash, admitted_with_id, status,
       created_at
FROM oauth_clients
WHERE tenant_id = $1 AND id = ANY($2)
