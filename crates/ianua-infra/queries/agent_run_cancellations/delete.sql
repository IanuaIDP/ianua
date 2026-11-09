-- Forgets the order to stop a run of a tenant, once the run has ended.
DELETE FROM agent_run_cancellations
WHERE tenant_id = $1 AND run_id = $2
