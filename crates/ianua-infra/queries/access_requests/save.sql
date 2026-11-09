-- Keeps an access request: a new one is added, a known one still pending
-- takes its new status and answer. One already answered, withdrawn or run
-- out is left as it is, so a second answer changes nothing. Who asked, for
-- what, why and when never change.
INSERT INTO access_requests
    (id, tenant_id, requester_kind, requester_id, requester_person, asked, asked_id, reason,
     length_seconds, status, approver_kind, approver_id, approver_person, answered_at,
     requested_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status,
    approver_kind = EXCLUDED.approver_kind,
    approver_id = EXCLUDED.approver_id,
    approver_person = EXCLUDED.approver_person,
    answered_at = EXCLUDED.answered_at
WHERE access_requests.tenant_id = EXCLUDED.tenant_id AND access_requests.status = 'pending'
