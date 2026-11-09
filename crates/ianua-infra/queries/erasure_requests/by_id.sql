-- The erasure request of a tenant with the given id.
SELECT id, user_id, reason, status, completed_at, requested_at, scheduled_at,
       cancel_token_hash, sent_to
FROM erasure_requests
WHERE tenant_id = $1 AND id = $2
