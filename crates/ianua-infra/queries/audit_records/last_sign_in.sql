-- When anyone of the given tenants last signed in, or NULL when nobody
-- ever did.
SELECT max(occurred_at) AS "last?"
FROM audit_records
WHERE tenant_id = ANY($1) AND event_type = 'authentication.login_succeeded'
