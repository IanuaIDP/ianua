-- Keeps an organization: a new one is added, a known one takes the new
-- values. Its creation time never changes.
INSERT INTO organizations
    (id, slug, name, contact_email, display_name, plan, negotiated_limits,
     status, suspended_by_member, suspended_by_platform, auth_config,
     created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (id) DO UPDATE SET
    slug = EXCLUDED.slug,
    name = EXCLUDED.name,
    contact_email = EXCLUDED.contact_email,
    display_name = EXCLUDED.display_name,
    plan = EXCLUDED.plan,
    negotiated_limits = EXCLUDED.negotiated_limits,
    status = EXCLUDED.status,
    suspended_by_member = EXCLUDED.suspended_by_member,
    suspended_by_platform = EXCLUDED.suspended_by_platform,
    auth_config = EXCLUDED.auth_config,
    updated_at = EXCLUDED.updated_at
