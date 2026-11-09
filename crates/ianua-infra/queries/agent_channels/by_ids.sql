-- The channels between agents of a tenant with the given ids.
SELECT id, sender_id, receiver_id, scope_kind, scope_value, max_class, opened_by_kind,
       opened_by_id, opened_at, expires_at, closed_at
FROM agent_channels
WHERE tenant_id = $1 AND id = ANY($2)
