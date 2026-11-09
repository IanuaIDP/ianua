-- Removes the tenant's log shipping target with the given id.
DELETE FROM log_shipping_targets
WHERE tenant_id = $1 AND id = $2
