-- Keeps a tenant's SCIM endpoint: a new one is added, the tenant's one
-- takes the new values. When it was set up never changes.
INSERT INTO scim_endpoints
    (tenant_id, bearer_token_hash, enabled, default_role_id, auto_activate,
     deactivate_on_remove, last_sync_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (tenant_id) DO UPDATE SET
    bearer_token_hash = EXCLUDED.bearer_token_hash,
    enabled = EXCLUDED.enabled,
    default_role_id = EXCLUDED.default_role_id,
    auto_activate = EXCLUDED.auto_activate,
    deactivate_on_remove = EXCLUDED.deactivate_on_remove,
    last_sync_at = EXCLUDED.last_sync_at
