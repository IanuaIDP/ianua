-- Removes at most $3 of a tenant's request records that finished before
-- $2, oldest first, found through the index by time.
DELETE FROM proxy_request_records
WHERE tenant_id = $1
  AND correlation_id IN (
      SELECT correlation_id
      FROM proxy_request_records
      WHERE tenant_id = $1 AND occurred_at < $2
      ORDER BY occurred_at
      LIMIT $3
  )
