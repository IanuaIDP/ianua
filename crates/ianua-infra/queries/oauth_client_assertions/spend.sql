-- Records that one client of one tenant used an assertion, kept until it
-- expires, answering its id only when this statement was the first use.
INSERT INTO oauth_client_assertions (tenant_id, client_id, jti, expires_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id, client_id, jti) DO NOTHING
RETURNING jti
