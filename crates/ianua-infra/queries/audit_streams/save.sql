-- Keeps an audit stream: a new one is added, a known one takes the new
-- values. Its tenant and creation time never change.
INSERT INTO audit_streams
    (id, tenant_id, name, destination, events, state, state_since, failures, pause_reason,
     created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    destination = EXCLUDED.destination,
    events = EXCLUDED.events,
    state = EXCLUDED.state,
    state_since = EXCLUDED.state_since,
    failures = EXCLUDED.failures,
    pause_reason = EXCLUDED.pause_reason,
    updated_at = EXCLUDED.updated_at
WHERE audit_streams.tenant_id = EXCLUDED.tenant_id
