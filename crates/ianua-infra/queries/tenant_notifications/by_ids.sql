-- The notifications of a tenant user's inbox that the ids name, in no
-- order.
SELECT id, event_type, category, severity, title, body, resource_id, reach, read, created_at
FROM tenant_notifications
WHERE tenant_id = $1 AND user_id = $2 AND id = ANY($3)
