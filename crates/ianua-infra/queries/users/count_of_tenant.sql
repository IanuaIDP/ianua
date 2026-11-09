-- How many accounts a tenant holds against its plan: every one, whatever
-- its standing, since a deactivated account comes back without a check.
SELECT count(*) AS "count!"
FROM users
WHERE tenant_id = $1
