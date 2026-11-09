-- The sign-ins of the given tenants in the window that succeeded and
-- failed, per bucket of the given unit, `hour` or `day`, in UTC, in time
-- order.
SELECT date_trunc($4, occurred_at, 'UTC') AS "bucket!",
       count(*) FILTER (WHERE event_type = 'authentication.login_succeeded') AS "succeeded!",
       count(*) FILTER (WHERE event_type = 'authentication.login_failed') AS "failed!"
FROM audit_records
WHERE tenant_id = ANY($1)
    AND event_type IN ('authentication.login_succeeded', 'authentication.login_failed')
    AND occurred_at >= $2 AND occurred_at < $3
GROUP BY 1
ORDER BY 1
