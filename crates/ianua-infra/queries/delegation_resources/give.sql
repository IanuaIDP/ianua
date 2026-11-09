-- Keeps the named resources one delegation of a tenant grants a relation
-- on, all in one statement, each relation at the same place in the two
-- lists as its resource. One listed twice is kept once.
INSERT INTO delegation_resources (tenant_id, delegation_id, relation, resource_ref)
SELECT $1, $2, given.relation, given.resource_ref
FROM UNNEST($3::text[], $4::text[]) AS given (relation, resource_ref)
ON CONFLICT DO NOTHING
