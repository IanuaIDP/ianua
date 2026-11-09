-- The topics of a tenant with the given ids.
SELECT id, name, topic_name, description, schema_definition, retention_kind, retention_amount,
       status, created_by_kind, created_by_id, created_by_person, data_class, created_at,
       updated_at
FROM topics
WHERE tenant_id = $1 AND id = ANY($2)
