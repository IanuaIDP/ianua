-- The link the tenant's next audit record is chained to, read under the
-- tenant's chain lock: its newest record, the anchor a purge left, or the
-- genesis link of 32 zero bytes at record 0.
SELECT link.seq AS "seq!", link.entry_hash AS "entry_hash!"
FROM (
    (SELECT r.seq, r.entry_hash FROM audit_records r
     WHERE r.tenant_id = $1 ORDER BY r.seq DESC LIMIT 1)
    UNION ALL
    (SELECT a.seq, a.entry_hash FROM audit_chain_anchors a WHERE a.tenant_id = $1)
    UNION ALL
    (SELECT 0::bigint, decode(repeat('00', 32), 'hex'))
) AS link
ORDER BY link.seq DESC
LIMIT 1
