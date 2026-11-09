-- Every tenant's active stream routes, each with its tenant, for the
-- gateway to bind their ports.
SELECT tenant_id, id, name, protocol, listen_port, sni, policy, access, backends,
       connect_timeout_secs, idle_timeout_secs, status, workflow_use, created_at, updated_at
FROM stream_routes
WHERE status = 'active'
ORDER BY tenant_id, id
