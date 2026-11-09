-- Every member of an organization who chose a channel for one category,
-- with the channel.
SELECT org_user_id AS holder, channel
FROM org_notification_preferences
WHERE organization_id = $1 AND category = $2
