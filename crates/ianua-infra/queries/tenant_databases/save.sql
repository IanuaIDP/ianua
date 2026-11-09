-- Records that a tenant lives in its schema from now on.
INSERT INTO tenant_databases (tenant_id, schema_name, registered_at)
VALUES ($1, $2, $3)
ON CONFLICT (tenant_id) DO NOTHING
