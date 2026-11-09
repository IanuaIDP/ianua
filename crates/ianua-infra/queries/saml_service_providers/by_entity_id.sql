-- The SAML app of a tenant that names itself by the given entity id.
SELECT id, name, entity_id, status, settings, created_at, updated_at
FROM saml_service_providers
WHERE tenant_id = $1 AND entity_id = $2
