-- A tenant's sealed chain head, if it has added any record.
SELECT seq, entry_hash, seal
FROM audit_chain_heads
WHERE tenant_id = $1
