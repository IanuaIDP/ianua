-- The member with the given id, only when they belong to the given
-- organization.
SELECT id, organization_id, email, display_name, password_hash, status, role,
       email_standing, locale, timezone, joined_at, credentials_changed_at,
       route_vouches, created_at, updated_at
FROM org_users
WHERE id = $1 AND organization_id = $2
