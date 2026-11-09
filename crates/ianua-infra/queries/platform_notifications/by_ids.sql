-- The notifications of an operator's inbox that the ids name, in no order.
SELECT id, event_type, category, severity, title, body, resource_id, reach, read, created_at
FROM platform_notifications
WHERE operator_id = $1 AND id = ANY($2)
