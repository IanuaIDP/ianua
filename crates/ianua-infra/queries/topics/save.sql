-- Keeps a topic: a new one is added, a known one of the same tenant takes
-- the new values. Its tenant, its name services publish to, its maker and
-- its creation time never change.
INSERT INTO topics
    (id, tenant_id, name, topic_name, description, schema_definition, retention_kind,
     retention_amount, status, created_by_kind, created_by_id, created_by_person, data_class,
     created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    schema_definition = EXCLUDED.schema_definition,
    retention_kind = EXCLUDED.retention_kind,
    retention_amount = EXCLUDED.retention_amount,
    status = EXCLUDED.status,
    data_class = EXCLUDED.data_class,
    updated_at = EXCLUDED.updated_at
WHERE topics.tenant_id = EXCLUDED.tenant_id
