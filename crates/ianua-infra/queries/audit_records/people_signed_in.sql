-- How many of the tenant's users signed in at least once in the window.
SELECT count(DISTINCT actor_id) AS "count!"
FROM audit_records
WHERE tenant_id = $1 AND event_type = 'authentication.login_succeeded'
    AND actor_kind = 'tenant_user' AND occurred_at >= $2 AND occurred_at < $3
