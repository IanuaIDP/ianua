-- Deletes the passkey ceremonies of one tenant, read from the database of
-- its own it lives in, that lapsed before the given time without an
-- answer, and counts them.
WITH purged AS (
    DELETE FROM passkey_ceremonies
    WHERE tenant_id = $1 AND expires_at < $2 AND consumed_at IS NULL
    RETURNING tenant_id
)
SELECT count(*) AS "purged!" FROM purged
