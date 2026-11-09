-- The tenants an organization member holds any grant in.
SELECT DISTINCT tenant_id
FROM org_tenant_grants
WHERE org_user_id = $1
ORDER BY tenant_id
