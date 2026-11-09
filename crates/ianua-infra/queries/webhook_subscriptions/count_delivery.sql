-- Counts one try on a webhook subscription of a tenant and keeps the try,
-- in one statement. Only the failure streak and what goes with it change,
-- each from the row as it stands when locked, so two tries at once both
-- count and an edit made meanwhile is kept.
--
-- A success ends the streak and is the last delivery. A failure adds one
-- to the streak, and switches an active subscription off when the streak
-- reaches the limit. Either way the subscription changes now. Answers the
-- subscription's id and whether this try switched it off, or nothing when
-- the subscription is gone.
WITH held AS (
    SELECT id, status
    FROM webhook_subscriptions
    WHERE tenant_id = $1 AND id = $2
    FOR UPDATE
),
counted AS (
    UPDATE webhook_subscriptions subscription
    SET consecutive_failures = CASE WHEN $8::text = 'success' THEN 0
                                    ELSE subscription.consecutive_failures + 1 END,
        last_delivered_at = CASE WHEN $8::text = 'success' THEN $3::timestamptz
                                 ELSE subscription.last_delivered_at END,
        status = CASE WHEN $8::text <> 'success' AND held.status = 'active'
                           AND subscription.consecutive_failures + 1 >= $4::bigint
                      THEN 'disabled'
                      ELSE subscription.status END,
        updated_at = $3::timestamptz
    FROM held
    WHERE subscription.tenant_id = $1 AND subscription.id = held.id
    RETURNING subscription.id, held.status = 'active' AND subscription.status = 'disabled'
        AS switched_off
),
kept AS (
    INSERT INTO webhook_deliveries
        (id, tenant_id, subscription_id, message_id, event_type, status, response_code,
         duration_ms, attempt_number, attempted_at)
    SELECT $5::uuid, $1::uuid, counted.id, $6::uuid, $7::text, $8::text, $9::integer,
           $10::bigint, $11::smallint, $12::timestamptz
    FROM counted
)
SELECT counted.id AS "id!", counted.switched_off AS "switched_off!"
FROM counted
