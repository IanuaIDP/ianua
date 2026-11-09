-- The SCIM endpoint of a tenant.
SELECT bearer_token_hash, enabled, default_role_id, auto_activate, deactivate_on_remove,
       last_sync_at, created_at
FROM scim_endpoints
WHERE tenant_id = $1
