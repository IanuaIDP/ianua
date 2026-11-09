-- Every active stream route of one tenant open to its workflows, by name:
-- the systems a Protected data step may reach.
SELECT tenant_id, id, name, protocol, listen_port, sni, policy, access, backends,
       connect_timeout_secs, idle_timeout_secs, status, workflow_use, created_at, updated_at
FROM stream_routes
WHERE tenant_id = $1 AND status = 'active' AND workflow_use = 'open'
ORDER BY name, id
