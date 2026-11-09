-- The audit records an agent made in the tenant after the given place in
-- the chain, oldest first, at most the given number.
SELECT seq, id, event_type, payload, occurred_at, entry_hash, prev_hash
FROM audit_records
WHERE tenant_id = $1 AND actor_kind = $2 AND actor_id = $3 AND seq > $4
ORDER BY seq
LIMIT $5
