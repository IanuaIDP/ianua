-- The erasure request with the given id, in the given organization.
SELECT id, organization_id, org_user_id, reason, status, completed_at,
       requested_at, scheduled_at, cancel_token_hash, sent_to
FROM org_erasure_requests
WHERE id = $1 AND organization_id = $2
