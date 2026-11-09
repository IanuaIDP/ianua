-- Keeps the agent runs one run of one tenant waits on, all in one
-- statement. A run already kept is left as it is.
INSERT INTO workflow_execution_runs (tenant_id, agent_run_id, execution_id)
SELECT $1::uuid, waited.agent_run_id, $2::uuid
FROM UNNEST($3::uuid[]) AS waited (agent_run_id)
ON CONFLICT (tenant_id, agent_run_id) DO NOTHING
