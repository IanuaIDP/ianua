-- Every tenant user who chose a channel for one category, with the channel.
SELECT user_id AS holder, channel
FROM notification_preferences
WHERE tenant_id = $1 AND category = $2
