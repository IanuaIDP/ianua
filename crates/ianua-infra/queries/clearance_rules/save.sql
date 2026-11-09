-- Keeps a tenant's clearance rules, replacing what was stored.
INSERT INTO clearance_rules (tenant_id, permissions, levels, updated_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id) DO UPDATE SET
    permissions = EXCLUDED.permissions,
    levels = EXCLUDED.levels,
    updated_at = EXCLUDED.updated_at
