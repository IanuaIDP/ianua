-- Saves a new tenant setup, and answers its tenant. A tenant that has one
-- already keeps it, and nothing comes back: of two starts at once, the
-- first one's setup is kept.
INSERT INTO tenant_setups (
    tenant_id, planned, done, failed_step, failed_reason, started_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_id) DO NOTHING
RETURNING tenant_id
