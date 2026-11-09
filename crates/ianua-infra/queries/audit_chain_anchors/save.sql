-- Keeps the last record a purge removed as the tenant's chain anchor, with
-- the purge's cutoff and the anchor's seal.
INSERT INTO audit_chain_anchors (tenant_id, seq, entry_hash, purged_before, seal)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id) DO UPDATE SET
    seq = EXCLUDED.seq,
    entry_hash = EXCLUDED.entry_hash,
    purged_before = EXCLUDED.purged_before,
    seal = EXCLUDED.seal
