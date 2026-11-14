-- Keeps how a push to a stream went, and nothing else, only while the
-- stream is still as the push read it: a person's pause, change or removal
-- since then wins, and no row is touched.
UPDATE signal_streams
SET status = $3,
    consecutive_failures = $4,
    updated_at = $5
WHERE tenant_id = $1 AND id = $2 AND updated_at = $6
