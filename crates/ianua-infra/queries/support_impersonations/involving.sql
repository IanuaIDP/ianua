-- Every support impersonation of a tenant naming the given user as the
-- admin or as the person acted as, newest first.
SELECT id, admin_id, user_id, reason, window_minutes, consent, status, since,
       requested_at
FROM support_impersonations
WHERE tenant_id = $1 AND (admin_id = $2 OR user_id = $2)
ORDER BY requested_at DESC, id DESC
