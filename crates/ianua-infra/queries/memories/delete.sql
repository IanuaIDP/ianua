-- Deletes one memory of a tenant once its texts are gone and its waiting
-- period is over; its entries go with it.
DELETE FROM memories
WHERE tenant_id = $1 AND id = $2 AND status = 'deletion_requested'
