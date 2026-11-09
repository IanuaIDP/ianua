-- Every signing key of a tenant, oldest first.
SELECT kid, algorithm, public_key, private_key_sealed, status, rotated_at, expires_at,
       created_at
FROM signing_keys
WHERE tenant_id = $1
ORDER BY created_at, kid
