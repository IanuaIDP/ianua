-- The recovery codes of a user's set, each with when it was used.
SELECT code_hash, used_at
FROM recovery_codes
WHERE tenant_id = $1 AND user_id = $2
ORDER BY code_hash
