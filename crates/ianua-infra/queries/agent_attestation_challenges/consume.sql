-- Spends the challenge a nonce holds for one agent of a tenant at the
-- given time, if it is unspent and valid then, and reads it back spent.
-- One statement, so two proofs racing for it cannot both spend it.
UPDATE agent_attestation_challenges
SET used_at = $4
WHERE tenant_id = $1 AND agent_id = $2 AND nonce = $3
  AND used_at IS NULL AND issued_at <= $4 AND expires_at > $4
RETURNING nonce, agent_id, issued_at, expires_at, used_at
