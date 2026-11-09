-- Whether a tenant has a user with the given id.
SELECT EXISTS (SELECT 1 FROM users WHERE tenant_id = $1 AND id = $2) AS "exists!"
