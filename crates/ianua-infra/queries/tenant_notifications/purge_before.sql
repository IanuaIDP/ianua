-- Removes a tenant's notifications made before the given moment, read or
-- not.
DELETE FROM tenant_notifications
WHERE tenant_id = $1 AND created_at < $2
