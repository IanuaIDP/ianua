-- Claims a listening port for one stream route of one tenant, or moves the
-- route's claim to its new port. A port another route holds, of any
-- tenant, refuses it.
INSERT INTO stream_route_ports (listen_port, tenant_id, stream_route_id)
VALUES ($1, $2, $3)
ON CONFLICT (tenant_id, stream_route_id) DO UPDATE SET
    listen_port = EXCLUDED.listen_port
