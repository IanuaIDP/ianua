-- The organization members with the given ids, in any organization.
SELECT id, organization_id, email, display_name, password_hash, status, role,
       email_standing, locale, timezone, joined_at, credentials_changed_at,
       route_vouches, created_at, updated_at
FROM org_users
WHERE id = ANY($1)
