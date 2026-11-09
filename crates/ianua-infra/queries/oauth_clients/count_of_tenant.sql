-- How many OAuth clients a tenant holds against its plan: every one not
-- revoked, since a revoked client never works again.
SELECT count(*) AS "count!"
FROM oauth_clients
WHERE tenant_id = $1 AND status <> 'revoked'
