-- Keeps a tenant's break-glass policy: a first one is added, a known one
-- takes what users may give themselves now and when that changed.
INSERT INTO break_glass_policies (tenant_id, self_service_system, self_service_custom, updated_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id) DO UPDATE SET
    self_service_system = EXCLUDED.self_service_system,
    self_service_custom = EXCLUDED.self_service_custom,
    updated_at = EXCLUDED.updated_at
