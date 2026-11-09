-- The pushed authorization request of one tenant with the given id, used
-- or not.
SELECT id, client_id, parameters, created_at, expires_at, used_at
FROM oauth_pushed_requests
WHERE tenant_id = $1 AND id = $2
