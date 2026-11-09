-- Spends one of a user's recovery codes at the given time, only if it is
-- still unused: a row changed means this call spent it.
UPDATE recovery_codes
SET used_at = $4
WHERE tenant_id = $1 AND user_id = $2 AND code_hash = $3 AND used_at IS NULL
