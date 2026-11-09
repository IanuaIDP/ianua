-- The anchor a retention purge left in a tenant's chain, if any, with its
-- seal.
SELECT seq, entry_hash, seal
FROM audit_chain_anchors
WHERE tenant_id = $1
