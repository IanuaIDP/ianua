-- How many sessions of the given tenants were active at the given moment:
-- made by then, not revoked or suspended, and not yet expired.
SELECT count(*) AS "count!"
FROM sessions
WHERE tenant_id = ANY($1) AND status = 'active' AND created_at <= $2 AND expires_at > $2
