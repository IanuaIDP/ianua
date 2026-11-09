-- Every assertion key of a tenant, oldest first, with its private half
-- still sealed, for the gateway, which opens the one that signs.
SELECT kid, algorithm, public_key, private_key_sealed, status, rotated_at, created_at
FROM assertion_keys
WHERE tenant_id = $1
ORDER BY created_at, kid
