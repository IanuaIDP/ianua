-- The last verdict of the sweep on the tenant's audit chain, with its seal.
SELECT verified_at, standing, broken_at_seq, checkpoint_seq, checkpoint_hash, seal
FROM audit_chain_verdicts
WHERE tenant_id = $1
