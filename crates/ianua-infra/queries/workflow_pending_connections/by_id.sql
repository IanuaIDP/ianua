-- One connection of one tenant, by its id.
SELECT id, integration, name, sharing, operations, place, started_by, state_hash, verifier_sealed,
    stage, credential_sealed, code_hash, expires_at, created_at, updated_at
FROM workflow_pending_connections
WHERE tenant_id = $1 AND id = $2
