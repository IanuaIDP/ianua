-- The requests of a tenant still to carry out, pending or failed and due a
-- retry, whose grace period ended by the given moment, oldest first.
SELECT id, user_id, reason, status, completed_at, requested_at, scheduled_at,
       cancel_token_hash, sent_to
FROM erasure_requests
WHERE tenant_id = $1 AND status IN ('pending', 'failed') AND scheduled_at <= $2
  AND (scheduled_at, id) > (COALESCE($3::timestamptz, '-infinity'::timestamptz),
                             COALESCE($4::uuid, '00000000-0000-0000-0000-000000000000'::uuid))
ORDER BY scheduled_at, id
LIMIT $5
