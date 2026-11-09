-- Keeps the delegations a minted delegation of a tenant was cut from, all
-- in one statement, each at its place in the list. A lineage never
-- changes, so one already kept stays as it is.
INSERT INTO delegation_sources (tenant_id, delegation_id, source_id, position)
SELECT $1, $2, given.source_id, given.position::integer
FROM UNNEST($3::uuid[]) WITH ORDINALITY AS given (source_id, position)
ON CONFLICT DO NOTHING
