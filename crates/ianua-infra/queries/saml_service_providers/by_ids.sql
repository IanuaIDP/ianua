-- The SAML apps of a tenant with the given ids.
SELECT id, name, entity_id, status, settings, created_at, updated_at
FROM saml_service_providers
WHERE tenant_id = $1 AND id = ANY($2)
