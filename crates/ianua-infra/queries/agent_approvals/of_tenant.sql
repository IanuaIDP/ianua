-- Every approval request of a tenant, whatever its agent, newest first, in
-- one status when one is given, without the people behind their
-- delegations. A request still pending past its time to decide counts as
-- expired, as the request itself reads, though no sweep saved it so.
SELECT id, agent_id, delegation_id, requested_by_kind, requested_by_id, requested_by_person,
       run_id, pending_tool, pending_arguments, pending_at_step, run_exposure, chain_depth,
       owner_kind, owner_id, owner_person, action_class, action, status, first_by_kind,
       first_by_id, first_by_person, first_at, decided_by_kind, decided_by_id,
       decided_by_person, decided_at, created_at, expires_at, updated_at
FROM agent_approvals
WHERE tenant_id = $1
  AND ($2::text IS NULL
       OR CASE WHEN status = 'pending' AND expires_at <= $3 THEN 'expired' ELSE status END = $2)
ORDER BY created_at DESC, id DESC
