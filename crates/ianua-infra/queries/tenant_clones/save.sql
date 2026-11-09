-- Saves a clone, new or changed.
INSERT INTO tenant_clones (
    id, tenant_id, source_tenant_id, organization_id, parts, copied, state, failure,
    ended_at, started_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (id) DO UPDATE
SET copied = EXCLUDED.copied,
    state = EXCLUDED.state,
    failure = EXCLUDED.failure,
    ended_at = EXCLUDED.ended_at
WHERE tenant_clones.tenant_id = EXCLUDED.tenant_id
