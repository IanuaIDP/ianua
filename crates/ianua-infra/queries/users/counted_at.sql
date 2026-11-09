-- How many people of the given tenants there were at the given moment:
-- every account made by then that is not deactivated or closing.
SELECT count(*) AS "count!"
FROM users
WHERE tenant_id = ANY($1) AND created_at <= $2
    AND status IN ('invited', 'pending_verification', 'active', 'locked')
