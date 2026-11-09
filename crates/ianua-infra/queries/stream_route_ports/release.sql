-- Releases the port one stream route of one tenant claims.
DELETE FROM stream_route_ports
WHERE tenant_id = $1 AND stream_route_id = $2
