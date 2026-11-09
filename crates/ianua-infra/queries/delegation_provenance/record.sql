-- Records that one delegation of a tenant derived its authority from each
-- of the given ones, all in one statement. An edge already recorded is
-- passed over, so recording twice changes nothing.
INSERT INTO delegation_provenance (tenant_id, delegation_id, source_id)
SELECT $1, $2, given.source_id
FROM UNNEST($3::uuid[]) AS given (source_id)
ON CONFLICT DO NOTHING
