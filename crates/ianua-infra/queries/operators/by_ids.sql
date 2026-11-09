-- The operators with the given ids.
SELECT id, email, password_hash, status, created_at
FROM operators
WHERE id = ANY($1)
