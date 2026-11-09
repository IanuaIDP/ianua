-- The channels of a tenant into one agent, from any agent, that no person
-- has closed, oldest first.
SELECT id, sender_id, receiver_id, scope_kind, scope_value, max_class, opened_by_kind,
       opened_by_id, opened_at, expires_at, closed_at
FROM agent_channels
WHERE tenant_id = $1 AND receiver_id = $2 AND closed_at IS NULL
ORDER BY opened_at, id
