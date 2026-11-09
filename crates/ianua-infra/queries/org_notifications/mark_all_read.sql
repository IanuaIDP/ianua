-- Marks every unread notification of a member's inbox read.
UPDATE org_notifications
SET read = true
WHERE organization_id = $1 AND org_user_id = $2 AND NOT read
