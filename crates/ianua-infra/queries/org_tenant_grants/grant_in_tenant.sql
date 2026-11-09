-- Grants an organization member roles in one tenant, all in one statement:
-- each role with who granted it (NULL for the platform) and when.
INSERT INTO org_tenant_grants (org_user_id, tenant_id, role_id, granted_by, granted_at)
SELECT $1, $2, granted.role_id, granted.granted_by, granted.granted_at
FROM UNNEST($3::uuid[], $4::uuid[], $5::timestamptz[])
    AS granted (role_id, granted_by, granted_at)
