-- Keeps an authorization request one tenant's client just pushed.
INSERT INTO oauth_pushed_requests
    (id, tenant_id, client_id, parameters, created_at, expires_at, used_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
