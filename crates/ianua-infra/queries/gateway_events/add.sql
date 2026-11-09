-- Adds events the gateway raised in one tenant to its inbox, each sealed by
-- the gateway, for the worker to append to the tenant's trail.
INSERT INTO gateway_events
    (id, tenant_id, event_type, subject, payload, seal, occurred_at, written_at)
SELECT added.id, $1, added.event_type, added.subject, added.payload, added.seal,
       added.occurred_at, now()
FROM UNNEST($2::uuid[], $3::text[], $4::text[], $5::text[], $6::text[], $7::timestamptz[])
    AS added (id, event_type, subject, payload, seal, occurred_at)
