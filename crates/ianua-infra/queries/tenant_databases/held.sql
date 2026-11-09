-- Whether a tenant lives in a schema of its own, read by the trail before
-- it adds a record to the platform's tables.
SELECT EXISTS (SELECT 1 FROM tenant_databases WHERE tenant_id = $1) AS "held!"
