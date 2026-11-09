-- Marks every unread notification of a tenant user's inbox read, whatever
-- it needs to be seen.
UPDATE tenant_notifications
SET read = true
WHERE tenant_id = $1 AND user_id = $2 AND NOT read
