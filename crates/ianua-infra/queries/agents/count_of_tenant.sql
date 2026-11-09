-- How many agent identities a tenant holds against its plan: every one not
-- revoked, suspended ones too, since a revoked agent never acts again.
SELECT count(*) AS "count!"
FROM agents
WHERE tenant_id = $1 AND status <> 'revoked'
