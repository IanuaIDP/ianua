-- Tenant identities for an organization's retained audit history, including deleted tenants.
SELECT ARRAY(
    SELECT t.id FROM tenants t
    WHERE t.organization_id = $1
    ORDER BY t.id
) AS "tenants!"
