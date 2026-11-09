-- Every channel a tenant user chose, by category.
SELECT category, channel
FROM notification_preferences
WHERE tenant_id = $1 AND user_id = $2
ORDER BY category
