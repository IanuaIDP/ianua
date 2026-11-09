-- Records a peer's logout request to a tenant as taken until it expires,
-- answering its id only when this statement was the one that took it.
INSERT INTO taken_logout_requests (tenant_id, issuer, request_id, expires_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id, issuer, request_id) DO NOTHING
RETURNING request_id
