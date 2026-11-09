-- Gives a group of a tenant the given roles, all in one statement, each
-- at its place in the list.
INSERT INTO group_roles (tenant_id, group_id, role_id, position)
SELECT $1, $2, given.role_id, given.position::integer
FROM UNNEST($3::uuid[]) WITH ORDINALITY AS given (role_id, position)
