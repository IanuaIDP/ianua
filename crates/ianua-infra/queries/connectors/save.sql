-- Keeps a connector: a new one is added, a known one of the same tenant
-- takes the new values. Its tenant and creation time never change, and
-- when the gateway last saw it is the gateway's to write.
INSERT INTO connectors
    (id, tenant_id, name, scope, code_hash, code_expires_at, public_key,
     certificate_expires_at, enrolled_at, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    scope = EXCLUDED.scope,
    code_hash = EXCLUDED.code_hash,
    code_expires_at = EXCLUDED.code_expires_at,
    public_key = EXCLUDED.public_key,
    certificate_expires_at = EXCLUDED.certificate_expires_at,
    enrolled_at = EXCLUDED.enrolled_at,
    status = EXCLUDED.status,
    updated_at = EXCLUDED.updated_at
WHERE connectors.tenant_id = EXCLUDED.tenant_id
