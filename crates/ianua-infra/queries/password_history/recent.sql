-- The given number of a user's latest retired password hashes, newest
-- first.
SELECT password_hash
FROM password_history
WHERE tenant_id = $1 AND user_id = $2
ORDER BY recorded_at DESC
LIMIT $3
