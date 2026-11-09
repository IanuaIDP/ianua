-- The members of an organization who might hold rights in one tenant: every
-- owner and admin, whose role reaches every tenant, and every member
-- holding a grant in it.
SELECT id, organization_id, email, display_name, password_hash, status, role,
       email_standing, locale, timezone, joined_at, credentials_changed_at,
       route_vouches, created_at, updated_at
FROM org_users
WHERE organization_id = $1
  AND (role IN ('owner', 'admin')
       OR id IN (SELECT org_user_id FROM org_tenant_grants WHERE tenant_id = $2))
ORDER BY id
