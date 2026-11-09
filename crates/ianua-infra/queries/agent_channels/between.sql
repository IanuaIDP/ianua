-- The channels of a tenant from one agent to another that no person has
-- closed, oldest first. Whether one has expired is the caller's to check.
SELECT id, sender_id, receiver_id, scope_kind, scope_value, max_class, opened_by_kind,
       opened_by_id, opened_at, expires_at, closed_at
FROM agent_channels
WHERE tenant_id = $1 AND sender_id = $2 AND receiver_id = $3 AND closed_at IS NULL
ORDER BY opened_at, id
