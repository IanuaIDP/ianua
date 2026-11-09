-- Writes the roles a connection's mapping gave an account of a tenant, all
-- in one statement, each at its place in the list.
INSERT INTO mapped_holding_roles (tenant_id, connection_id, user_id, role_id, position)
SELECT $1, $2, $3, given.role_id, given.position::integer
FROM UNNEST($4::uuid[]) WITH ORDINALITY AS given (role_id, position)
