-- Records that one agent of one tenant signed in with an assertion, kept
-- until it expires, answering its id only when this statement was the
-- first use.
INSERT INTO agent_assertions (tenant_id, agent_id, jti, expires_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id, agent_id, jti) DO NOTHING
RETURNING jti
