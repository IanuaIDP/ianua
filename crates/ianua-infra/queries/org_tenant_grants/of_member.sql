-- Every grant an organization member holds, across the tenants.
SELECT org_user_id, tenant_id, role_id, granted_by, granted_at
FROM org_tenant_grants
WHERE org_user_id = $1
ORDER BY tenant_id, role_id
