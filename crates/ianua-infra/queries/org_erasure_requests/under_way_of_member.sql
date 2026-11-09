-- The erasure request of a member of an organization still under way:
-- neither completed nor cancelled.
SELECT id, organization_id, org_user_id, reason, status, completed_at,
       requested_at, scheduled_at, cancel_token_hash, sent_to
FROM org_erasure_requests
WHERE organization_id = $1 AND org_user_id = $2
  AND status NOT IN ('completed', 'cancelled')
