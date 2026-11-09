-- Keeps a user: a new one is added, a known one of the same tenant takes
-- the new values. Its tenant and creation time never change.
INSERT INTO users
    (id, tenant_id, email, display_name, status, email_verified, locale, timezone,
     given_name, family_name, preferred_username, picture, phone_number,
     external_id, department, manager_id, employee_number,
     created_at, updated_at, last_login_at, joined_at, credentials_changed_at,
     route_vouches)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
        $18, $19, $20, $21, $22, $23)
ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    display_name = EXCLUDED.display_name,
    status = EXCLUDED.status,
    email_verified = EXCLUDED.email_verified,
    locale = EXCLUDED.locale,
    timezone = EXCLUDED.timezone,
    given_name = EXCLUDED.given_name,
    family_name = EXCLUDED.family_name,
    preferred_username = EXCLUDED.preferred_username,
    picture = EXCLUDED.picture,
    phone_number = EXCLUDED.phone_number,
    external_id = EXCLUDED.external_id,
    department = EXCLUDED.department,
    manager_id = EXCLUDED.manager_id,
    employee_number = EXCLUDED.employee_number,
    updated_at = EXCLUDED.updated_at,
    last_login_at = EXCLUDED.last_login_at,
    joined_at = EXCLUDED.joined_at,
    credentials_changed_at = EXCLUDED.credentials_changed_at,
    route_vouches = EXCLUDED.route_vouches
WHERE users.tenant_id = EXCLUDED.tenant_id
