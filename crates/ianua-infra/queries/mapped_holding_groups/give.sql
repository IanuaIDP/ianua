-- Writes the groups a connection's mapping put an account of a tenant in,
-- all in one statement, each at its place in the list.
INSERT INTO mapped_holding_groups (tenant_id, connection_id, user_id, group_id, position)
SELECT $1, $2, $3, given.group_id, given.position::integer
FROM UNNEST($4::uuid[]) WITH ORDINALITY AS given (group_id, position)
