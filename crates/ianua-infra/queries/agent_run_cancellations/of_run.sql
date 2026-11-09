-- The order to stop one run of a tenant, if one was given.
SELECT run_id, ordered_by_kind, ordered_by_id, ordered_by_person, ordered_at
FROM agent_run_cancellations
WHERE tenant_id = $1 AND run_id = $2
