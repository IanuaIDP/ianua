-- Deletes one API key of one tenant, as revoking it does.
DELETE FROM api_keys
WHERE tenant_id = $1 AND id = $2
