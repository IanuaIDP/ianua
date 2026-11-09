-- Keeps a channel between agents: a new one is added, a known one of the
-- same tenant takes when it was closed. What it carries, between whom, who
-- opened it and for how long never change.
INSERT INTO agent_channels
    (id, tenant_id, sender_id, receiver_id, scope_kind, scope_value, max_class, opened_by_kind,
     opened_by_id, opened_at, expires_at, closed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (id) DO UPDATE SET
    closed_at = EXCLUDED.closed_at
WHERE agent_channels.tenant_id = EXCLUDED.tenant_id
