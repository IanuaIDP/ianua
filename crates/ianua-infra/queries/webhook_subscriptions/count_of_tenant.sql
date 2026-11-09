-- How many webhook subscriptions a tenant holds against its plan, paused
-- and disabled ones too.
SELECT count(*) AS "count!"
FROM webhook_subscriptions
WHERE tenant_id = $1
