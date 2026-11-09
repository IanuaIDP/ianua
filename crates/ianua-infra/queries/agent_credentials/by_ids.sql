-- The agent credentials of a tenant with the given ids.
SELECT id, agent_id, kid, algorithm, public_key, status, rotated_at, attested_method,
       attested_subject, created_at, expires_at, updated_at
FROM agent_credentials
WHERE tenant_id = $1 AND id = ANY($2)
