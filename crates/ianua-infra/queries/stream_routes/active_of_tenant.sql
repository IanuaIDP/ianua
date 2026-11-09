-- One tenant's active stream routes, read from the database of its own it
-- lives in, for the gateway to bind their ports.
SELECT tenant_id, id, name, protocol, listen_port, sni, policy, access, backends,
       connect_timeout_secs, idle_timeout_secs, status, workflow_use, created_at, updated_at
FROM stream_routes
WHERE tenant_id = $1 AND status = 'active'
ORDER BY id
