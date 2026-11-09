-- Every consent one person of one tenant gave, to any client, newest
-- first, withdrawn ones too.
SELECT user_id, client_id, scopes, granted_at
FROM oauth_consents
WHERE tenant_id = $1 AND user_id = $2
ORDER BY granted_at DESC, client_id DESC
