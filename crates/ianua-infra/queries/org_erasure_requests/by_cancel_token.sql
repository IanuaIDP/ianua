-- The erasure request whose cancel link carries the token with the given
-- hash, in whichever organization.
SELECT id, organization_id, org_user_id, reason, status, completed_at,
       requested_at, scheduled_at, cancel_token_hash, sent_to
FROM org_erasure_requests
WHERE cancel_token_hash = $1
