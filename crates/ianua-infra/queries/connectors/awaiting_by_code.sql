-- The connector of one tenant still awaiting enrollment with the given
-- code hash. An enrolled connector keeps no code, so it matches nothing.
SELECT id, name, scope, code_hash, code_expires_at, public_key,
       certificate_expires_at, enrolled_at, status, last_seen_at, created_at,
       updated_at
FROM connectors
WHERE tenant_id = $1 AND code_hash = $2
LIMIT 1
