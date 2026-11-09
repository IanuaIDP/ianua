-- Forgets the login of one stream route closed to workflows.
DELETE FROM stream_route_logins
WHERE tenant_id = $1 AND stream_route_id = $2
