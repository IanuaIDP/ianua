-- The oldest request of a tenant still waiting for a decision on exactly
-- one action under one delegation, while its time to decide has not run
-- out.
SELECT id, agent_id, delegation_id, requested_by_kind, requested_by_id, requested_by_person,
       run_id, pending_tool, pending_arguments, pending_at_step, run_exposure, chain_depth,
       owner_kind, owner_id, owner_person, action_class, action, status, first_by_kind,
       first_by_id, first_by_person, first_at, decided_by_kind, decided_by_id,
       decided_by_person, decided_at, created_at, expires_at, updated_at
FROM agent_approvals
WHERE tenant_id = $1 AND delegation_id = $2 AND status = 'pending' AND action = $3
  AND $4 < expires_at
ORDER BY created_at, id
LIMIT 1
