-- Every delegation of a tenant that loses its authority when the given
-- one is revoked: its sub-delegations, the tokens minted from it and the
-- delegations a token exchange derived from it, and theirs in turn. The
-- given one is left out, and a loop stored by mistake ends the walk.
WITH RECURSIVE reached (id) AS (
    SELECT $2::uuid
    UNION
    SELECT edge.derived
    FROM reached
    CROSS JOIN LATERAL (
        SELECT child.id AS derived
        FROM agent_delegations child
        WHERE child.tenant_id = $1 AND child.parent_id = reached.id
        UNION ALL
        SELECT minted.delegation_id
        FROM delegation_sources minted
        WHERE minted.tenant_id = $1 AND minted.source_id = reached.id
        UNION ALL
        SELECT derived.delegation_id
        FROM delegation_provenance derived
        WHERE derived.tenant_id = $1 AND derived.source_id = reached.id
    ) AS edge
)
SELECT reached.id AS "id!"
FROM reached
WHERE reached.id <> $2
