-- Records a new code carrying a single sign-on back to the dashboard. One
-- already recorded is left as it is, so saving it again never brings back
-- a code already taken.
INSERT INTO sign_in_codes
    (tenant_id, token_hash, dashboard_hash, session_id, expires_at, consumed_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_id, token_hash) DO NOTHING
