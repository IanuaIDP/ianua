-- Removes the tenants' records the bus took.
DELETE FROM event_outbox
WHERE tenant_id = ANY($1) AND record_id = ANY($2)
