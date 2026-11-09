-- The directory service account of a tenant with the given name.
SELECT id, name, secret_hash, access, base_dns, status, created_at, secret_changed_at
FROM directory_service_accounts
WHERE tenant_id = $1 AND name = $2
