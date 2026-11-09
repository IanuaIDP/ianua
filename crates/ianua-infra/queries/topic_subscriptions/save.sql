-- Keeps a subscription: a new one is added, a known one of the same tenant
-- takes the new values. Its tenant, its topic, its service and its creation
-- time never change.
INSERT INTO topic_subscriptions
    (id, tenant_id, topic_name, consumer_id, consumer_group, delivery_mode, push_url,
     push_secret_sealed, previous_secret_sealed, previous_secret_until, ack_deadline_seconds,
     max_deliveries, filter, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
ON CONFLICT (id) DO UPDATE SET
    consumer_group = EXCLUDED.consumer_group,
    delivery_mode = EXCLUDED.delivery_mode,
    push_url = EXCLUDED.push_url,
    push_secret_sealed = EXCLUDED.push_secret_sealed,
    previous_secret_sealed = EXCLUDED.previous_secret_sealed,
    previous_secret_until = EXCLUDED.previous_secret_until,
    ack_deadline_seconds = EXCLUDED.ack_deadline_seconds,
    max_deliveries = EXCLUDED.max_deliveries,
    filter = EXCLUDED.filter,
    status = EXCLUDED.status,
    updated_at = EXCLUDED.updated_at
WHERE topic_subscriptions.tenant_id = EXCLUDED.tenant_id
