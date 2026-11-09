-- Keeps an integration account: a new one is added, a known one takes its
-- new values. Its integration, owner and when it was connected never
-- change.
INSERT INTO integration_accounts
    (id, tenant_id, integration, name, credential_sealed, owner, sharing, operations, status,
     created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    credential_sealed = EXCLUDED.credential_sealed,
    sharing = EXCLUDED.sharing,
    operations = EXCLUDED.operations,
    status = EXCLUDED.status,
    updated_at = EXCLUDED.updated_at
WHERE integration_accounts.tenant_id = EXCLUDED.tenant_id
