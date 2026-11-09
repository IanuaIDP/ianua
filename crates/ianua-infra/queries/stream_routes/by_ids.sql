-- The stream routes of one tenant with the given ids.
SELECT tenant_id, id, name, protocol, listen_port, sni, policy, access, backends,
       connect_timeout_secs, idle_timeout_secs, status, workflow_use, created_at, updated_at
FROM stream_routes
WHERE tenant_id = $1 AND id = ANY($2)
