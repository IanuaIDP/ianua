-- Records that a tenant no longer lives in a schema of its own.
DELETE FROM tenant_databases
WHERE tenant_id = $1
