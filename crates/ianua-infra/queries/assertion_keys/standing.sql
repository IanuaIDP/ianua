-- Writes the standing of a tenant's known assertion keys in one statement.
-- A key's algorithm, its two halves and its creation time never change.
UPDATE assertion_keys
SET status = kept.status, rotated_at = kept.rotated_at
FROM UNNEST($2::text[], $3::text[], $4::timestamptz[]) AS kept (kid, status, rotated_at)
WHERE assertion_keys.tenant_id = $1 AND assertion_keys.kid = kept.kid
