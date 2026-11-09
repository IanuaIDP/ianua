-- Takes every group mapping rule off a connection of a tenant.
DELETE FROM connection_group_rules
WHERE tenant_id = $1 AND connection_id = $2
