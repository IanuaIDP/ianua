-- How many private network connectors a tenant holds against its plan:
-- every one not revoked, since a revoked connector never works again.
SELECT count(*) AS "count!"
FROM connectors
WHERE tenant_id = $1 AND status <> 'revoked'
