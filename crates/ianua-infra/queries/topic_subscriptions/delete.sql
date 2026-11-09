-- Removes a subscription of the tenant for good.
DELETE FROM topic_subscriptions
WHERE tenant_id = $1 AND id = $2
