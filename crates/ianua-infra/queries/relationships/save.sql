-- Writes a new relationship of a tenant. The same fact twice is refused by
-- relationships_fact_key.
INSERT INTO relationships
    (id, tenant_id, object_type, object_key, link, relation, subject_kind, subject_id,
     parent_type, parent_key, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
