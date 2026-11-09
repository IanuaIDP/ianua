-- The delegations one agent of a tenant holds, oldest first, each with
-- the delegations a minted one was cut from, in their order.
SELECT d.id, d.delegator_kind, d.delegator_id, d.delegate_id, d.granted, d.limits, d.lineage,
       d.parent_id, d.minted_delegator_kind, d.minted_delegator_id, d.minted_credential_id,
       ARRAY(
           SELECT s.source_id
           FROM delegation_sources s
           WHERE s.tenant_id = d.tenant_id AND s.delegation_id = d.id
           ORDER BY s.position
       ) AS "minted_from!",
       d.depth, d.status, d.issued_at, d.expires_at, d.renewed_at, d.updated_at, d.name
FROM agent_delegations d
WHERE d.tenant_id = $1 AND d.delegate_id = $2
ORDER BY d.issued_at, d.id
