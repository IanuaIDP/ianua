-- The public half of every signing key of a tenant that is not revoked,
-- newest first, for the gateway, whose role reads no private key.
SELECT kid, algorithm, public_key, status, rotated_at, expires_at, created_at
FROM signing_keys
WHERE tenant_id = $1 AND status <> 'revoked'
ORDER BY created_at DESC, kid DESC
