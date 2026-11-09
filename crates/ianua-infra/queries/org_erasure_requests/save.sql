-- Keeps an erasure request: a new one is added, a known one takes its new
-- standing. Who asked, why, when, and the link it mailed never change, and
-- a request of another organization under the same id is left as it is.
INSERT INTO org_erasure_requests
    (id, organization_id, org_user_id, reason, status, completed_at,
     requested_at, scheduled_at, cancel_token_hash, sent_to)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status,
    completed_at = EXCLUDED.completed_at
WHERE org_erasure_requests.organization_id = EXCLUDED.organization_id
