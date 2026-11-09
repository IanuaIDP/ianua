-- The request of a user of a tenant still under way, pending or being
-- carried out, the latest first.
SELECT id, user_id, reason, status, completed_at, requested_at, scheduled_at,
       cancel_token_hash, sent_to
FROM erasure_requests
WHERE tenant_id = $1 AND user_id = $2 AND status IN ('pending', 'processing')
ORDER BY requested_at DESC
LIMIT 1
