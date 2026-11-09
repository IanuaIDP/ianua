-- Every directory service account of a tenant, by name.
SELECT id, name, secret_hash, access, base_dns, status, created_at, secret_changed_at
FROM directory_service_accounts
WHERE tenant_id = $1
ORDER BY name
