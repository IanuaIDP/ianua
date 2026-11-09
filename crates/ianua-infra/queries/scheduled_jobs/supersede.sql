-- Marks the given dead jobs superseded: a later job did their work.
UPDATE scheduled_jobs
SET status = 'superseded'
WHERE tenant_id IS NOT DISTINCT FROM $1 AND id = ANY($2) AND status = 'dead'
