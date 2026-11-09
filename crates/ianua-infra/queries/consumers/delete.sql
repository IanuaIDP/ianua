-- Removes a consumer of the tenant for good.
DELETE FROM consumers
WHERE tenant_id = $1 AND id = $2
