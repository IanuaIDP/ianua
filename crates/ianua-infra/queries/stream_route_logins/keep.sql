-- Keeps the login of one stream route open to workflows, in place of any
-- kept before.
INSERT INTO stream_route_logins (
    tenant_id, stream_route_id, login_user, login_password, tls, tls_authority, tls_server_name
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_id, stream_route_id) DO UPDATE SET
    login_user = EXCLUDED.login_user,
    login_password = EXCLUDED.login_password,
    tls = EXCLUDED.tls,
    tls_authority = EXCLUDED.tls_authority,
    tls_server_name = EXCLUDED.tls_server_name
