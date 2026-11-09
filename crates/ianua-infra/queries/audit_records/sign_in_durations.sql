-- The measured times of the successful sign-ins of the given tenants in
-- the window, their total in milliseconds and how many were measured.
SELECT coalesce(sum((payload -> 'value' ->> 'auth_duration_ms')::bigint), 0)::bigint
           AS "total!",
       count(payload -> 'value' ->> 'auth_duration_ms') AS "measured!"
FROM audit_records
WHERE tenant_id = ANY($1)
    AND event_type = 'authentication.login_succeeded'
    AND occurred_at >= $2 AND occurred_at < $3
