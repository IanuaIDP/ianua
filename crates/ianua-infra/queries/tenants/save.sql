-- Keeps a tenant: a new one is added, a known one takes the new values. Its
-- organization and creation time never change.
INSERT INTO tenants
    (id, organization_id, slug, display_name, primary_domain, contact_email,
     status, held, archived_at, compliance, auth_config, mtls, timezone, locale,
     residency, customer_cloud, environment, created_at, updated_at, platform_label, readable_address)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
ON CONFLICT (id) DO UPDATE SET
    slug = EXCLUDED.slug,
    display_name = EXCLUDED.display_name,
    primary_domain = EXCLUDED.primary_domain,
    contact_email = EXCLUDED.contact_email,
    status = EXCLUDED.status,
    held = EXCLUDED.held,
    archived_at = EXCLUDED.archived_at,
    compliance = EXCLUDED.compliance,
    auth_config = EXCLUDED.auth_config,
    mtls = EXCLUDED.mtls,
    timezone = EXCLUDED.timezone,
    locale = EXCLUDED.locale,
    residency = EXCLUDED.residency,
    customer_cloud = EXCLUDED.customer_cloud,
    environment = EXCLUDED.environment,
    readable_address = EXCLUDED.readable_address,
    updated_at = EXCLUDED.updated_at
