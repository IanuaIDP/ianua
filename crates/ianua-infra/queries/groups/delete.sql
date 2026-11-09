-- Deletes a group of a tenant, with the roles it carries and its members.
-- One with groups under it is kept by its foreign key.
DELETE FROM groups
WHERE tenant_id = $1 AND id = $2
