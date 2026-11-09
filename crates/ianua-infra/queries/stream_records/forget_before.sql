-- Removes at most $3 of a tenant's stream records that ended before $2,
-- oldest first, found through the index by time.
DELETE FROM stream_records
WHERE tenant_id = $1
  AND id IN (
      SELECT id
      FROM stream_records
      WHERE tenant_id = $1 AND occurred_at < $2
      ORDER BY occurred_at
      LIMIT $3
  )
