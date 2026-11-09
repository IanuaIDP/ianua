-- The grants the given members hold in one tenant.
SELECT org_user_id, role_id, granted_by, granted_at
FROM org_tenant_grants
WHERE tenant_id = $1 AND org_user_id = ANY($2)
ORDER BY org_user_id, role_id
