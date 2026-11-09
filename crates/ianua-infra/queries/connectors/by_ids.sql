-- The connectors of one tenant with the given ids.
SELECT id, name, scope, code_hash, code_expires_at, public_key,
       certificate_expires_at, enrolled_at, status, last_seen_at, created_at,
       updated_at
FROM connectors
WHERE tenant_id = $1 AND id = ANY($2)
