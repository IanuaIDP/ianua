-- The notifications of a member's inbox that the ids name, in no order.
SELECT id, event_type, category, severity, title, body, resource_id, reach, read, created_at
FROM org_notifications
WHERE organization_id = $1 AND org_user_id = $2 AND id = ANY($3)
