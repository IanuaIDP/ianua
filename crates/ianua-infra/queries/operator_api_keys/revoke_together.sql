-- Revokes keys of one operator still in force, each at its own time, the
-- prefixes and times given as two arrays of the same order. Run after the
-- keys were locked, so every one named is written.
UPDATE operator_api_keys AS kept
SET revoked_at = revoked.at
FROM unnest($2::text[], $3::timestamptz[]) AS revoked(key_prefix, at)
WHERE kept.operator_id = $1
    AND kept.key_prefix = revoked.key_prefix
    AND kept.revoked_at IS NULL
