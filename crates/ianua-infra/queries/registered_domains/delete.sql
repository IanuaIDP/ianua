-- Deletes one registered domain of one tenant.
DELETE FROM registered_domains
WHERE tenant_id = $1 AND id = $2
