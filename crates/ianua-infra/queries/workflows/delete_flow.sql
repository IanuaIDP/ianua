-- Deletes one agent flow of one tenant, and with it its version, its run
-- and its webhook secret. A designed workflow is never deleted, so one is
-- left as it is.
DELETE FROM workflows
WHERE tenant_id = $1 AND id = $2 AND origin = 'flow'
