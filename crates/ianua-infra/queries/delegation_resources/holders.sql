-- The agents holding a relation on one named resource of a tenant
-- through a delegation neither revoked nor expired at the given time,
-- the oldest delegation first.
SELECT d.delegate_id, r.relation
FROM delegation_resources r
JOIN agent_delegations d ON d.tenant_id = r.tenant_id AND d.id = r.delegation_id
WHERE r.tenant_id = $1 AND r.resource_ref = $2 AND d.status = 'active' AND d.expires_at > $3
ORDER BY d.issued_at, d.id, r.relation
