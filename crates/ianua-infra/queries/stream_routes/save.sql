-- Keeps a stream route: a new one is added, a known one of the same tenant
-- takes the new values. Its tenant and creation time never change.
INSERT INTO stream_routes
    (id, tenant_id, name, protocol, listen_port, sni, policy, access, backends,
     connect_timeout_secs, idle_timeout_secs, status, workflow_use, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    protocol = EXCLUDED.protocol,
    listen_port = EXCLUDED.listen_port,
    sni = EXCLUDED.sni,
    policy = EXCLUDED.policy,
    access = EXCLUDED.access,
    backends = EXCLUDED.backends,
    connect_timeout_secs = EXCLUDED.connect_timeout_secs,
    idle_timeout_secs = EXCLUDED.idle_timeout_secs,
    status = EXCLUDED.status,
    workflow_use = EXCLUDED.workflow_use,
    updated_at = EXCLUDED.updated_at
WHERE stream_routes.tenant_id = EXCLUDED.tenant_id
