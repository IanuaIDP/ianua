-- The requested runs and their ordered steps from one statement snapshot,
-- so a concurrent worker cannot pair an old header with newer steps.
SELECT id, agent_id, provider_id, goal, purpose, granted_tools, approval_classes, approval,
       delegation_id, max_steps, spend_limit_micros, input_tokens, output_tokens, spent_micros,
       started_by_kind, started_by_id, started_by_person, exposure, chain_depth, status,
       pending_call, created_at, updated_at, spend_check, spend_check_micros,
       check_version_id, check_tries,
       ARRAY(SELECT s.step FROM agent_run_steps s
             WHERE s.tenant_id = $1 AND s.run_id = r.id
             ORDER BY s.seq) AS "steps!"
FROM agent_runs r
WHERE tenant_id = $1 AND id = ANY($2)
