-- Removes every value a tenant's users hold under one attribute.
DELETE FROM user_metadata
WHERE tenant_id = $1 AND namespace = $2 AND key = $3
