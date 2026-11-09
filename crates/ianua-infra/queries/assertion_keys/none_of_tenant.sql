-- Whether one tenant, read from the database of its own it lives in,
-- holds no assertion key at all.
SELECT NOT EXISTS (SELECT 1 FROM assertion_keys WHERE tenant_id = $1) AS "none!"
