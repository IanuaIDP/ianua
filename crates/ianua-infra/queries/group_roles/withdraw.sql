-- Takes every role a group of a tenant carries off it.
DELETE FROM group_roles
WHERE tenant_id = $1 AND group_id = $2
