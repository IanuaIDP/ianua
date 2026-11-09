-- The operator signing in with the given address.
SELECT id, email, password_hash, status, created_at
FROM operators
WHERE email = $1
