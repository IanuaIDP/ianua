-- Marks one notification of a member's inbox read; a second time changes
-- nothing but still finds it.
UPDATE org_notifications
SET read = true
WHERE organization_id = $1 AND org_user_id = $2 AND id = $3
