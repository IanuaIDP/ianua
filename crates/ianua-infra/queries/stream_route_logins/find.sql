-- The login kept for one stream route open to workflows.
SELECT login_user, login_password, tls, tls_authority, tls_server_name
FROM stream_route_logins
WHERE tenant_id = $1 AND stream_route_id = $2
