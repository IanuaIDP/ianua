-- Removes a connection of a tenant, and with it its rules, links, mapped
-- holdings and the sign-ins in flight through it.
DELETE FROM federation_connections
WHERE tenant_id = $1 AND id = $2
