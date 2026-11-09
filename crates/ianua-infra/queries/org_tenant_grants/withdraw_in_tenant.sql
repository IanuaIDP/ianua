-- Withdraws every grant an organization member holds in one tenant.
DELETE FROM org_tenant_grants
WHERE tenant_id = $2 AND org_user_id = $1
