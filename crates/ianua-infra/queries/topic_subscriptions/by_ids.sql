-- The subscriptions of a tenant with the given ids.
SELECT id, topic_name, consumer_id, consumer_group, delivery_mode, push_url, push_secret_sealed,
       previous_secret_sealed, previous_secret_until, ack_deadline_seconds, max_deliveries,
       filter, status, created_at, updated_at
FROM topic_subscriptions
WHERE tenant_id = $1 AND id = ANY($2)
