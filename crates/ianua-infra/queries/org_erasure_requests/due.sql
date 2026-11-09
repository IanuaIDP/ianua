-- The erasure requests of every organization still to be carried out:
-- pending ones whose grace period ended by the given time, and failed
-- ones due a retry, the longest due first.
SELECT id, organization_id, org_user_id, reason, status, completed_at,
       requested_at, scheduled_at, cancel_token_hash, sent_to
FROM org_erasure_requests
WHERE status IN ('pending', 'failed')
  AND (status = 'failed' OR scheduled_at <= $1)
  AND (scheduled_at, id) > (COALESCE($2::timestamptz, '-infinity'::timestamptz),
                             COALESCE($3::uuid, '00000000-0000-0000-0000-000000000000'::uuid))
ORDER BY scheduled_at, id
LIMIT $4
