-- Whether one tenant, read from the database of its own it lives in,
-- holds assertion keys but none active made at or after the cutoff.
SELECT (
    EXISTS (SELECT 1 FROM assertion_keys WHERE tenant_id = $1)
    AND NOT EXISTS (
        SELECT 1 FROM assertion_keys
        WHERE tenant_id = $1 AND status = 'active' AND created_at >= $2
    )
) AS "due!"
