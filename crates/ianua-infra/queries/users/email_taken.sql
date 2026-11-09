-- Whether a user of the tenant already has the given address.
SELECT EXISTS (SELECT 1 FROM users WHERE tenant_id = $1 AND email = $2) AS "taken!"
