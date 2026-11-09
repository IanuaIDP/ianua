-- The tenant of an organization with the given slug.
SELECT id, organization_id, slug, display_name, primary_domain, contact_email,
       status, held, archived_at, compliance, auth_config, mtls, timezone, locale,
       residency, environment, created_at, updated_at, platform_label, readable_address
FROM tenants
WHERE slug = $1 AND organization_id = $2
