-- Marks one notification of an operator's inbox read; a second time
-- changes nothing but still finds it.
UPDATE platform_notifications
SET read = true
WHERE operator_id = $1 AND id = $2
