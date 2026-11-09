-- Queues newly added organization and platform audit records for the
-- message bus.
INSERT INTO platform_event_outbox (record_id, queued_at)
SELECT queued.id, now()
FROM UNNEST($1::uuid[]) AS queued (id)
