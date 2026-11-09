-- Keeps a try at sending a message to a webhook subscription of the
-- tenant without counting it. The subscription is looked up within the
-- tenant, so one that is gone, or another tenant's, keeps nothing.
INSERT INTO webhook_deliveries
    (id, tenant_id, subscription_id, message_id, event_type, status, response_code,
     duration_ms, attempt_number, attempted_at)
SELECT $3::uuid, subscription.tenant_id, subscription.id, $4::uuid, $5::text, $6::text,
       $7::integer, $8::bigint, $9::smallint, $10::timestamptz
FROM webhook_subscriptions subscription
WHERE subscription.tenant_id = $1 AND subscription.id = $2
