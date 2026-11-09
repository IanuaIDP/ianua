-- Deletes the passkey ceremonies of every tenant in this database that
-- lapsed before the given time without an answer, and counts them: the
-- sweep's work across tenants.
WITH purged AS (
    DELETE FROM passkey_ceremonies
    WHERE expires_at < $1 AND consumed_at IS NULL
    RETURNING tenant_id
)
SELECT count(*) AS "purged!" FROM purged
