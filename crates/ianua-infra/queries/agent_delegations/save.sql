-- Keeps a delegation: a new one is added, a known one of the same tenant
-- takes the new values. Who granted it, who holds it, where it sits in its
-- chain, the key a minted one was minted with and when it was issued never
-- change, and a revoked one stays revoked, whatever a copy read before the
-- revoke says.
INSERT INTO agent_delegations
    (id, tenant_id, delegator_kind, delegator_id, delegate_id, granted, limits, lineage,
     parent_id, minted_delegator_kind, minted_delegator_id, depth, status, issued_at,
     expires_at, renewed_at, updated_at, name, minted_credential_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
ON CONFLICT (id) DO UPDATE SET
    granted = EXCLUDED.granted,
    limits = EXCLUDED.limits,
    status = CASE
        WHEN agent_delegations.status = 'revoked' THEN 'revoked'
        ELSE EXCLUDED.status
    END,
    expires_at = EXCLUDED.expires_at,
    renewed_at = EXCLUDED.renewed_at,
    updated_at = GREATEST(EXCLUDED.updated_at, agent_delegations.updated_at),
    name = EXCLUDED.name
WHERE agent_delegations.tenant_id = EXCLUDED.tenant_id
