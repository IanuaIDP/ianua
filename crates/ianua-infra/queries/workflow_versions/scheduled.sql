-- The schedule of the version in service of each workflow named that
-- starts on one, with the tenant holding it, whichever tenant that is.
SELECT tenant_id, workflow_id, trigger_schedule AS "trigger_schedule!"
FROM workflow_versions
WHERE workflow_id = ANY($1) AND status = 'published' AND trigger_kind = 'schedule'
