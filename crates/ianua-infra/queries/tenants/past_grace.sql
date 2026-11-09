-- The archived tenants archived at or before the given time, the longest
-- archived first.
SELECT id
FROM tenants
WHERE status = 'archived' AND archived_at <= $1
ORDER BY archived_at, id
LIMIT $2
