-- Removes one value of a user of a tenant, leaving the rest.
DELETE FROM user_metadata
WHERE tenant_id = $1 AND user_id = $2 AND namespace = $3 AND key = $4
