-- Deletes a role of a tenant. The roles given straight to people go with
-- it; one a group still carries is kept by its foreign key.
DELETE FROM roles
WHERE tenant_id = $1 AND id = $2
