-- Adds a notification to an operator's inbox; adding it again changes
-- nothing.
INSERT INTO platform_notifications (
    id, operator_id, event_type, category, severity, title, body, resource_id, reach, read,
    created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (id) DO NOTHING
