-- The id of a subscription of a consumer group on a topic, other than the
-- one given, if the group has one.
SELECT id
FROM topic_subscriptions
WHERE tenant_id = $1 AND topic_name = $2 AND consumer_group = $3 AND id <> $4
ORDER BY id
LIMIT 1
