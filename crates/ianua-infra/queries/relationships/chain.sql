-- Relationships for a batch of objects and their ancestors, once per row,
-- following parents at most the given number of steps from each root.
WITH RECURSIVE reached (object_type, object_key, depth) AS (
    SELECT roots.object_type, roots.object_key, 0
    FROM unnest($2::text[], $3::text[]) AS roots(object_type, object_key)
    UNION
    SELECT up.parent_type, up.parent_key, reached.depth + 1
    FROM relationships up
    JOIN reached ON up.object_type = reached.object_type AND up.object_key = reached.object_key
    WHERE up.tenant_id = $1 AND up.link = 'under' AND reached.depth < $4
)
SELECT r.id, r.object_type, r.object_key, r.link, r.relation, r.subject_kind, r.subject_id,
       r.parent_type, r.parent_key, r.created_at
FROM relationships r
WHERE r.tenant_id = $1
  AND (r.object_type, r.object_key) IN (
      SELECT reached.object_type, reached.object_key FROM reached
  )
ORDER BY r.created_at, r.id
