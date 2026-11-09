-- A credential of a tenant issued against an attestation of the given
-- subject, held by an agent other than the one given, if one is.
SELECT id, agent_id, kid, algorithm, public_key, status, rotated_at, attested_method,
       attested_subject, created_at, expires_at, updated_at
FROM agent_credentials
WHERE tenant_id = $1 AND attested_subject = $2 AND agent_id <> $3
ORDER BY created_at, id
LIMIT 1
