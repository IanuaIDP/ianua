-- Keeps an erasure request: a new one is added, a known one of the same
-- tenant takes where it stands. Whose it is, why, when it was asked, when
-- it may start and its cancel link never change.
INSERT INTO erasure_requests
    (id, tenant_id, user_id, reason, status, completed_at, requested_at,
     scheduled_at, cancel_token_hash, sent_to)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status,
    completed_at = EXCLUDED.completed_at
WHERE erasure_requests.tenant_id = EXCLUDED.tenant_id
