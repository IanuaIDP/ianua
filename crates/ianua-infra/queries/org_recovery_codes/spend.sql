-- Spends one of a member's recovery codes at the given time, only if it is
-- still unused: a row changed means this call spent it.
UPDATE org_recovery_codes
SET used_at = $3
WHERE org_user_id = $1 AND code_hash = $2 AND used_at IS NULL
