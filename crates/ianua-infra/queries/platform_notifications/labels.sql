-- The titles of an operator's notifications with the given ids, for the audit trail to name them by.
SELECT id, title AS name
FROM platform_notifications
WHERE operator_id = $1 AND id = ANY($2)
