-- Locks the keys of one operator among the given prefixes still in force,
-- and answers their prefixes, so a revocation of them together writes all
-- of them or none: a key revoked meanwhile is left out of the answer.
SELECT key_prefix
FROM operator_api_keys
WHERE operator_id = $1 AND key_prefix = ANY($2) AND revoked_at IS NULL
FOR UPDATE
