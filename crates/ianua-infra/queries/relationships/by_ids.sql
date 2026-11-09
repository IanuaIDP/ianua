-- The relationships of a tenant with the given ids.
SELECT id, object_type, object_key, link, relation, subject_kind, subject_id,
       parent_type, parent_key, created_at
FROM relationships
WHERE tenant_id = $1 AND id = ANY($2)
