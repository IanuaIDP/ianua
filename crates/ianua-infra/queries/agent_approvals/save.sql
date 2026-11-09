-- Keeps an approval request: a new one is added, a known one of the same
-- tenant takes its new standing, approvals and decision. Its tenant, its
-- agent, where it came from, the action it is about, its people and its
-- times to raise and close never change. A known one is written over only
-- while it still waits, when an approval is spent, or when the same
-- decision is written again, so a copy read before another decision never
-- undoes a denial or makes a spent approval whole again.
INSERT INTO agent_approvals
    (id, tenant_id, agent_id, delegation_id, requested_by_kind, requested_by_id,
     requested_by_person, run_id, pending_tool, pending_arguments, pending_at_step,
     run_exposure, chain_depth, owner_kind, owner_id, owner_person, action_class, action,
     status, first_by_kind, first_by_id, first_by_person, first_at, decided_by_kind,
     decided_by_id, decided_by_person, decided_at, created_at, expires_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
        $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status,
    first_by_kind = EXCLUDED.first_by_kind,
    first_by_id = EXCLUDED.first_by_id,
    first_by_person = EXCLUDED.first_by_person,
    first_at = EXCLUDED.first_at,
    decided_by_kind = EXCLUDED.decided_by_kind,
    decided_by_id = EXCLUDED.decided_by_id,
    decided_by_person = EXCLUDED.decided_by_person,
    decided_at = EXCLUDED.decided_at,
    updated_at = EXCLUDED.updated_at
WHERE agent_approvals.tenant_id = EXCLUDED.tenant_id
  AND (
      agent_approvals.status = 'pending'
      OR (agent_approvals.status = 'approved' AND EXCLUDED.status = 'consumed')
      OR (agent_approvals.status = EXCLUDED.status
          AND agent_approvals.decided_by_kind IS NOT DISTINCT FROM EXCLUDED.decided_by_kind
          AND agent_approvals.decided_by_id IS NOT DISTINCT FROM EXCLUDED.decided_by_id
          AND agent_approvals.decided_at IS NOT DISTINCT FROM EXCLUDED.decided_at)
  )
