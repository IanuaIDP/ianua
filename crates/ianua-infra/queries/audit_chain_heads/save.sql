-- Moves a tenant's sealed chain head to the newest link the trail added.
INSERT INTO audit_chain_heads (tenant_id, seq, entry_hash, seal)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id) DO UPDATE SET
    seq = EXCLUDED.seq,
    entry_hash = EXCLUDED.entry_hash,
    seal = EXCLUDED.seal
