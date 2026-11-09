-- The access requests of a tenant with the given ids.
SELECT id, requester_kind, requester_id, requester_person, asked, asked_id, reason,
       length_seconds, status, approver_kind, approver_id, approver_person, answered_at,
       requested_at
FROM access_requests
WHERE tenant_id = $1 AND id = ANY($2)
