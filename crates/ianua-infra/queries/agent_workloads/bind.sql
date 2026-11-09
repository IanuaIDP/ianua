-- Binds a workload identity of a tenant to the agent it bootstrapped, and
-- answers that agent. Binding it to the same agent again changes nothing;
-- nothing comes back when another agent holds it, even one bound at the
-- same moment.
INSERT INTO agent_workloads (tenant_id, attested_subject, agent_id)
VALUES ($1, $2, $3)
ON CONFLICT (tenant_id, attested_subject) DO UPDATE SET agent_id = EXCLUDED.agent_id
WHERE agent_workloads.agent_id = EXCLUDED.agent_id
RETURNING agent_id
