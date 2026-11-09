-- Adds the new steps of a run of a tenant in one statement. A step is
-- never changed once it is kept, so one already stored stays as it is.
INSERT INTO agent_run_steps (tenant_id, run_id, seq, step)
SELECT $1, $2, kept.seq, kept.step
FROM UNNEST($3::integer[], $4::jsonb[]) AS kept (seq, step)
ON CONFLICT (tenant_id, run_id, seq) DO NOTHING
