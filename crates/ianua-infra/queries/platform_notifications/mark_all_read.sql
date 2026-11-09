-- Marks every unread notification of an operator's inbox read.
UPDATE platform_notifications
SET read = true
WHERE operator_id = $1 AND NOT read
