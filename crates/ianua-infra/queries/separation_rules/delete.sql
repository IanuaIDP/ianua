-- Removes a separation rule of a tenant.
DELETE FROM separation_rules
WHERE tenant_id = $1 AND id = $2
