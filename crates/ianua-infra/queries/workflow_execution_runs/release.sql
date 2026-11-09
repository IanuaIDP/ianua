-- Lets go of the agent runs one run of one tenant no longer waits on.
DELETE FROM workflow_execution_runs
WHERE tenant_id = $1 AND execution_id = $2 AND agent_run_id <> ALL($3)
