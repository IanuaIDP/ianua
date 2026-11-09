-- The support impersonation of a tenant with the given id.
SELECT id, admin_id, user_id, reason, window_minutes, consent, status, since,
       requested_at
FROM support_impersonations
WHERE tenant_id = $1 AND id = $2
