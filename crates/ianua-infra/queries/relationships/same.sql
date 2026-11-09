-- The relationship of a tenant saying the same about the same object, if
-- one was written: the fact its unique constraint keeps to one row.
SELECT id, object_type, object_key, link, relation, subject_kind, subject_id,
       parent_type, parent_key, created_at
FROM relationships
WHERE tenant_id = $1 AND object_type = $2 AND object_key = $3 AND link = $4
  AND relation IS NOT DISTINCT FROM $5::text
  AND subject_kind IS NOT DISTINCT FROM $6::text
  AND subject_id IS NOT DISTINCT FROM $7::uuid
  AND parent_type IS NOT DISTINCT FROM $8::text
  AND parent_key IS NOT DISTINCT FROM $9::text
