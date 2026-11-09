-- Records a newly opened passkey ceremony. One already recorded is left as
-- it is: only settling it changes it, so saving it again can never reopen
-- a ceremony already settled.
INSERT INTO passkey_ceremonies
    (id, tenant_id, user_id, purpose, state, created_at, expires_at, consumed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO NOTHING
