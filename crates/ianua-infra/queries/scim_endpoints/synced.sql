-- Writes when a tenant's SCIM endpoint last synced, and nothing else: its
-- token and settings stay as stored.
UPDATE scim_endpoints
SET last_sync_at = $2
WHERE tenant_id = $1
