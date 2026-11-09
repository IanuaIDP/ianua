-- The OAuth client of one tenant whose public client id is the given one,
-- whatever its status.
SELECT id, client_id_value, credential, name, redirect_uris, post_logout_redirect_uris,
       grant_types, scopes, settings, registration_token_hash, admitted_with_id, status,
       created_at
FROM oauth_clients
WHERE tenant_id = $1 AND client_id_value = $2
