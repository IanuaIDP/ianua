-- The recovery codes of a member's set, each with when it was used.
SELECT code_hash, used_at
FROM org_recovery_codes
WHERE org_user_id = $1
ORDER BY code_hash
