-- The user of a tenant with the given address.
SELECT id, email, display_name, status, email_verified, locale, timezone,
       given_name, family_name, preferred_username, picture, phone_number,
       external_id, department, manager_id, employee_number,
       created_at, updated_at, last_login_at, joined_at, credentials_changed_at,
       route_vouches
FROM users
WHERE tenant_id = $1 AND email = $2
