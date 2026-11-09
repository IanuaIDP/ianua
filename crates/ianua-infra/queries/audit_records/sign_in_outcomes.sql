-- How many sign-ins of the given tenants succeeded and failed in the
-- window, from their audit records.
SELECT count(*) FILTER (WHERE event_type = 'authentication.login_succeeded') AS "succeeded!",
       count(*) FILTER (WHERE event_type = 'authentication.login_failed') AS "failed!"
FROM audit_records
WHERE tenant_id = ANY($1)
    AND event_type IN ('authentication.login_succeeded', 'authentication.login_failed')
    AND occurred_at >= $2 AND occurred_at < $3
