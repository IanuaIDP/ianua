-- Records a challenge issued to one agent of a tenant. A nonce already
-- recorded keeps its row, so a repeated nonce never makes a spent
-- challenge whole again.
INSERT INTO agent_attestation_challenges
    (tenant_id, nonce, agent_id, issued_at, expires_at, used_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_id, nonce) DO NOTHING
