-- Every operator who chose a channel for one category, with the channel.
SELECT operator_id AS holder, channel
FROM operator_notification_preferences
WHERE category = $1
