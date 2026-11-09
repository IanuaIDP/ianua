-- Removes a webhook subscription of the tenant for good, with its
-- messages and every try at sending them.
DELETE FROM webhook_subscriptions
WHERE tenant_id = $1 AND id = $2
