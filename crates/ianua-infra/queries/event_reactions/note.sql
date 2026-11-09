-- Notes that one monitor of one tenant acted on one event, answering the
-- event's id only when this statement made the note.
INSERT INTO event_reactions (tenant_id, reaction, record_id, noted_at)
VALUES ($1, $2, $3, now())
ON CONFLICT (tenant_id, reaction, record_id) DO NOTHING
RETURNING record_id
