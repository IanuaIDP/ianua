-- Removes a tenant's declaration of the given namespace and key.
DELETE FROM user_attribute_definitions
WHERE tenant_id = $1 AND namespace = $2 AND key = $3
