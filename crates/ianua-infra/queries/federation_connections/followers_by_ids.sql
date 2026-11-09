-- The tenant and id of each connection with the given ids that follows a
-- metadata address, across the tenants the transaction may see.
SELECT tenant_id, id
FROM federation_connections
WHERE id = ANY($1) AND follows_metadata
