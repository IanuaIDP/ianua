-- Marks one notification of a tenant user's inbox read; a second time
-- changes nothing but still finds it.
UPDATE tenant_notifications
SET read = true
WHERE tenant_id = $1 AND user_id = $2 AND id = $3
