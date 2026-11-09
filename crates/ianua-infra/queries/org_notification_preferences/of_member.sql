-- Every channel an organization member chose, by category.
SELECT category, channel
FROM org_notification_preferences
WHERE organization_id = $1 AND org_user_id = $2
ORDER BY category
