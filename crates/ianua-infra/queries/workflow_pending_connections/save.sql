-- Keeps a connection: a new one is added, a known one takes how far it
-- got. What it connects, who began it, its state and verifier and when it
-- runs out never change. Another connection's state refuses it.
INSERT INTO workflow_pending_connections
    (id, tenant_id, integration, name, sharing, operations, place, started_by, state_hash,
     verifier_sealed, stage, credential_sealed, code_hash, expires_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
ON CONFLICT (id) DO UPDATE SET
    stage = EXCLUDED.stage,
    credential_sealed = EXCLUDED.credential_sealed,
    code_hash = EXCLUDED.code_hash,
    updated_at = EXCLUDED.updated_at
WHERE workflow_pending_connections.tenant_id = EXCLUDED.tenant_id
