-- One memory's texts in the order they were kept, from $3 when a page
-- before named where this one starts, at most $4: one more than a page, so
-- the extra row says where the next page starts.
SELECT id, text, exposure, created_at AS kept_at
FROM memory_entries
WHERE tenant_id = $1 AND memory_id = $2 AND ($3::uuid IS NULL OR id >= $3)
ORDER BY id
LIMIT $4
