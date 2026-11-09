-- The oldest of the tenants' records still to be published, with what the
-- bus carries of them, locked for this relay; another relay passes over
-- them.
SELECT o.record_id AS id, o.tenant_id, r.organization_id, r.actor, r.event_type, r.payload,
       r.occurred_at, o.chain_depth
FROM event_outbox o
JOIN audit_records r ON r.id = o.record_id
ORDER BY o.queued_at, o.record_id
LIMIT $1
FOR UPDATE OF o SKIP LOCKED
