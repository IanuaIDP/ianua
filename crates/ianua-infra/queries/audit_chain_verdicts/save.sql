-- Keeps the sweep's verdict on the tenant's audit chain, sealed, replacing
-- the one before.
INSERT INTO audit_chain_verdicts
    (tenant_id, verified_at, standing, broken_at_seq, checkpoint_seq, checkpoint_hash, seal)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_id) DO UPDATE SET
    verified_at = EXCLUDED.verified_at,
    standing = EXCLUDED.standing,
    broken_at_seq = EXCLUDED.broken_at_seq,
    checkpoint_seq = EXCLUDED.checkpoint_seq,
    checkpoint_hash = EXCLUDED.checkpoint_hash,
    seal = EXCLUDED.seal
