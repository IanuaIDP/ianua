-- Every tenant living in a schema of its own, for a node to route by at
-- start and when it reloads, at most as many as the node will hold.
SELECT tenant_id, schema_name
FROM tenant_databases
ORDER BY tenant_id
LIMIT $1
