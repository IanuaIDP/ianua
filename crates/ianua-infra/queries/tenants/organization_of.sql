-- The organization a tenant belongs to, while the tenant is not deleted,
-- for a credential found in it.
SELECT organization_id
FROM tenants
WHERE id = $1 AND status <> 'deleted'
