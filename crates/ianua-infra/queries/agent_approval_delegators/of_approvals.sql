-- The people behind the delegations of the given approval requests of a
-- tenant, by request and in the order each request names them.
SELECT approval_id, account_kind, account_id, person
FROM agent_approval_delegators
WHERE tenant_id = $1 AND approval_id = ANY($2)
ORDER BY approval_id, place
