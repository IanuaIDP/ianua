-- Keeps a directory service account: a new one is added, a known one of
-- the same tenant takes the new values. Its tenant and creation time never
-- change.
INSERT INTO directory_service_accounts
    (id, tenant_id, name, secret_hash, access, base_dns, status, created_at,
     secret_changed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    secret_hash = EXCLUDED.secret_hash,
    access = EXCLUDED.access,
    base_dns = EXCLUDED.base_dns,
    status = EXCLUDED.status,
    secret_changed_at = EXCLUDED.secret_changed_at
WHERE directory_service_accounts.tenant_id = EXCLUDED.tenant_id
