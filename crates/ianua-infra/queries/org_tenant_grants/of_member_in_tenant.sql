-- The grants an organization member holds in one tenant.
SELECT org_user_id, tenant_id, role_id, granted_by, granted_at
FROM org_tenant_grants
WHERE tenant_id = $2 AND org_user_id = $1
ORDER BY role_id
