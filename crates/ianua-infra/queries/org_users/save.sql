-- Keeps an organization member: a new one is added, a known one takes the
-- new values. Their organization and creation time never change.
INSERT INTO org_users
    (id, organization_id, email, display_name, password_hash, status, role,
     email_standing, locale, timezone, joined_at, credentials_changed_at,
     route_vouches, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    display_name = EXCLUDED.display_name,
    password_hash = EXCLUDED.password_hash,
    status = EXCLUDED.status,
    role = EXCLUDED.role,
    email_standing = EXCLUDED.email_standing,
    locale = EXCLUDED.locale,
    timezone = EXCLUDED.timezone,
    joined_at = EXCLUDED.joined_at,
    credentials_changed_at = EXCLUDED.credentials_changed_at,
    route_vouches = EXCLUDED.route_vouches,
    updated_at = EXCLUDED.updated_at
