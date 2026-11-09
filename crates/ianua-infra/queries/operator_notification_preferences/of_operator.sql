-- Every channel an operator chose, by category.
SELECT category, channel
FROM operator_notification_preferences
WHERE operator_id = $1
ORDER BY category
