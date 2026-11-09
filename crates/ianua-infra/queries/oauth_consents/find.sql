-- The consent one person of one tenant gave one client.
SELECT user_id, client_id, scopes, granted_at
FROM oauth_consents
WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3
