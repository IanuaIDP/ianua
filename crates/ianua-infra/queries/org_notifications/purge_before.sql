-- Removes every organization member's notifications made before the given
-- moment, read or not.
DELETE FROM org_notifications
WHERE created_at < $1
