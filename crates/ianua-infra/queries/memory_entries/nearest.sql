-- One memory's texts whose vectors are nearest $3 by cosine, nearest first,
-- at most $4, with how alike each is (1 for the same direction) and when it
-- was kept.
SELECT id, text, exposure, created_at AS kept_at,
       (1 - (embedding <=> $3::text::vector))::float4 AS "similarity!"
FROM memory_entries
WHERE tenant_id = $1 AND memory_id = $2
ORDER BY embedding <=> $3::text::vector, id
LIMIT $4
