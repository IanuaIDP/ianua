-- Queues a tenant's newly added audit records for the message bus, each
-- with the depth of the workflow chain whose work raised it.
INSERT INTO event_outbox (tenant_id, record_id, queued_at, chain_depth)
SELECT $1, queued.id, now(), queued.chain_depth
FROM UNNEST($2::uuid[], $3::smallint[]) AS queued (id, chain_depth)
