-- The oldest organization and platform records still to be published,
-- with what the bus carries of them, locked for this relay; another relay
-- passes over them.
SELECT o.record_id AS id, r.organization_id, r.actor, r.event_type, r.payload, r.occurred_at
FROM platform_event_outbox o
JOIN platform_audit_records r ON r.id = o.record_id
ORDER BY o.queued_at, o.record_id
LIMIT $1
FOR UPDATE OF o SKIP LOCKED
