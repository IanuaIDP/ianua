-- The last record of the stretch at the start of the tenant's chain that
-- happened before the cutoff: the records up to the first one kept, so
-- those left still link one to the next.
SELECT r.seq, r.entry_hash
FROM audit_records r
WHERE r.tenant_id = $1
  AND r.seq < coalesce(
      (SELECT min(k.seq) FROM audit_records k WHERE k.tenant_id = $1 AND k.occurred_at >= $2),
      9223372036854775807
  )
ORDER BY r.seq DESC
LIMIT 1
