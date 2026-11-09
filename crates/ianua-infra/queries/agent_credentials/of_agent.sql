-- The credentials one agent of a tenant holds, active and rotated, oldest
-- first.
SELECT id, agent_id, kid, algorithm, public_key, status, rotated_at, attested_method,
       attested_subject, created_at, expires_at, updated_at
FROM agent_credentials
WHERE tenant_id = $1 AND agent_id = $2
ORDER BY created_at, id
