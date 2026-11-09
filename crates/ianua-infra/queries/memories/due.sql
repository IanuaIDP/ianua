-- The tenants in this database holding a memory whose waiting period is
-- over at $1.
SELECT DISTINCT tenant_id
FROM memories
WHERE status = 'deletion_requested' AND deleted_after <= $1
