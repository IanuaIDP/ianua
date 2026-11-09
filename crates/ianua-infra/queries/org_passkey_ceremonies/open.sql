-- Records a newly opened passkey ceremony. One already recorded is left as
-- it is: only settling it changes it, so saving it again can never reopen
-- a ceremony already settled.
INSERT INTO org_passkey_ceremonies
    (id, org_user_id, purpose, state, created_at, expires_at, consumed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (id) DO NOTHING
