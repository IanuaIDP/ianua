-- Keeps how a stream's sends went, and nothing else, only while the stream
-- is still as the delivery read it: a person's pause, change or removal
-- since then wins, and no row is touched.
UPDATE audit_streams
SET state = $3,
    state_since = $4,
    failures = $5,
    pause_reason = $6,
    updated_at = $7
WHERE tenant_id = $1 AND id = $2 AND updated_at = $8
