-- Removes every value one user of a tenant holds, in both namespaces.
DELETE FROM user_metadata
WHERE tenant_id = $1 AND user_id = $2
