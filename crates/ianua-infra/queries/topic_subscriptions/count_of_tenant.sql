-- How many subscriptions a tenant's message topics hold against its plan,
-- paused ones too.
SELECT count(*) AS "count!"
FROM topic_subscriptions
WHERE tenant_id = $1
