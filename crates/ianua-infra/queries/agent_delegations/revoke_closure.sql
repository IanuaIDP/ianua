-- Revokes a delegation of a tenant and every one that loses its authority
-- with it, at the given time, in one statement, and reads back only those
-- this changed: one already revoked is left alone and not named.
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
UPDATE agent_delegations d
SET status = 'revoked', updated_at = GREATEST($3, d.updated_at)
WHERE d.tenant_id = $1 AND d.status = 'active' AND d.id IN (SELECT reached.id FROM reached)
RETURNING d.id, d.delegate_id
