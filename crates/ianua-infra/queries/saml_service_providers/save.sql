-- Keeps a SAML app: a new one is added, a known one of the same tenant
-- takes the new values. Its tenant and creation time never change.
INSERT INTO saml_service_providers
    (id, tenant_id, name, entity_id, status, settings, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    entity_id = EXCLUDED.entity_id,
    status = EXCLUDED.status,
    settings = EXCLUDED.settings,
    updated_at = EXCLUDED.updated_at
WHERE saml_service_providers.tenant_id = EXCLUDED.tenant_id
