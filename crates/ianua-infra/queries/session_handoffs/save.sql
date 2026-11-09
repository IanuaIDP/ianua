-- Records a new pass carrying a session to another host. One already
-- recorded is left as it is, so saving it again never brings back a pass
-- already taken.
INSERT INTO session_handoffs
    (tenant_id, token_hash, browser_hash, session_id, service_id, host, expires_at, consumed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (tenant_id, token_hash) DO NOTHING
