-- The schema a tenant lives in, if it lives in one of its own.
SELECT schema_name
FROM tenant_databases
WHERE tenant_id = $1
