-- Whose the trusted device of a tenant with the given id is, and whether it
-- is still trusted: never the digest of its secret.
SELECT user_id, status
FROM trusted_devices
WHERE tenant_id = $1 AND id = $2
