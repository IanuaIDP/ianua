-- Every descendant per root, with cycles deduplicated independently for each root.
WITH RECURSIVE reached(root, id) AS (
    SELECT roots.id, roots.id FROM unnest($2::uuid[]) AS roots(id)
    UNION
    SELECT reached.root, edge.derived
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
    ) edge
)
SELECT reached.root AS "root!", reached.id AS "id!"
FROM reached
WHERE reached.id <> reached.root
