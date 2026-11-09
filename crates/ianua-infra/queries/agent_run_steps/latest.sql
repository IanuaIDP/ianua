-- The number of the last step stored for a run of a tenant, or zero when
-- none is.
SELECT coalesce(max(seq), 0) AS "latest!"
FROM agent_run_steps
WHERE tenant_id = $1 AND run_id = $2
