-- Keeps a raised view of an operation's risk: a new one is added, a known
-- one takes its new class and who raised it. Its operation and when it was
-- first set never change. Another override of the same operation refuses
-- it.
INSERT INTO operation_risk_overrides
    (id, tenant_id, integration, operation, effect, raised_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
    effect = EXCLUDED.effect,
    raised_by = EXCLUDED.raised_by,
    updated_at = EXCLUDED.updated_at
WHERE operation_risk_overrides.tenant_id = EXCLUDED.tenant_id
