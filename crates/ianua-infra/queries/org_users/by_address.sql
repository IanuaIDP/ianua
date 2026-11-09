-- Every organization's account at the given address, one per organization.
SELECT id, organization_id, email, display_name, password_hash, status, role,
       email_standing, locale, timezone, joined_at, credentials_changed_at,
       route_vouches, created_at, updated_at
FROM org_users
WHERE email = $1
ORDER BY organization_id
