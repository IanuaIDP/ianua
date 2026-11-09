-- The integration accounts of one tenant that the ids name.
SELECT id, integration, name, credential_sealed, owner, sharing, operations, status,
    created_at, updated_at
FROM integration_accounts
WHERE tenant_id = $1 AND id = ANY($2)
