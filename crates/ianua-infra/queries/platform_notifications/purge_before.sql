-- Removes every operator's notifications made before the given moment, read
-- or not.
DELETE FROM platform_notifications
WHERE created_at < $1
