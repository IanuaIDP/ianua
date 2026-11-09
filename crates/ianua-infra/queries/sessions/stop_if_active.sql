-- Writes a session's stopped status, only while it is still active: of two
-- requests that both saw it look taken over, one row changes and only that
-- request records the event.
UPDATE sessions
SET status = $3
WHERE tenant_id = $1 AND id = $2 AND status = 'active'
