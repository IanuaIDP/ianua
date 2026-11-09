-- Gives a connection of a tenant its group mapping rules, all in one
-- statement, each at its place in the list: the provider's group, whether
-- it brings a role or a group, and which.
INSERT INTO connection_group_rules
    (tenant_id, connection_id, position, provider_group, role_id, group_id)
SELECT $1, $2, given.position::integer, given.provider_group,
       CASE WHEN given.kind = 'role' THEN given.grant_id END,
       CASE WHEN given.kind = 'group' THEN given.grant_id END
FROM UNNEST($3::text[], $4::text[], $5::uuid[]) WITH ORDINALITY
    AS given (provider_group, kind, grant_id, position)
