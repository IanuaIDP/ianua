-- Deletes one run of one tenant, and with it the agent runs it waits on
-- and any run that starts it again.
DELETE FROM workflow_executions
WHERE tenant_id = $1 AND id = $2
