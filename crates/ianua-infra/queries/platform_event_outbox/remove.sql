-- Removes the organization and platform records the bus took.
DELETE FROM platform_event_outbox
WHERE record_id = ANY($1)
