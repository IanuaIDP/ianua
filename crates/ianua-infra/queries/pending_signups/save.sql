-- Keeps a sign-up until its link comes back: a new one is added, one under
-- the same link takes the new values.
INSERT INTO pending_signups
    (token_hash, email, company_name, tenant_name, admin_display_name, password_hash,
     timezone, locale, requested_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (token_hash) DO UPDATE SET
    email = EXCLUDED.email,
    company_name = EXCLUDED.company_name,
    tenant_name = EXCLUDED.tenant_name,
    admin_display_name = EXCLUDED.admin_display_name,
    password_hash = EXCLUDED.password_hash,
    timezone = EXCLUDED.timezone,
    locale = EXCLUDED.locale,
    requested_at = EXCLUDED.requested_at,
    expires_at = EXCLUDED.expires_at
