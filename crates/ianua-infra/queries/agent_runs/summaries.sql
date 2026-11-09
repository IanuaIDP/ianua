-- The runs of a tenant with the given ids, without their steps.
SELECT id, agent_id, provider_id, goal, purpose, granted_tools, approval_classes, approval,
       delegation_id, max_steps, spend_limit_micros, input_tokens, output_tokens, spent_micros,
       started_by_kind, started_by_id, started_by_person, exposure, chain_depth, status,
       pending_call, created_at, updated_at, spend_check, spend_check_micros, check_version_id,
       check_tries, ARRAY[]::jsonb[] AS "steps!"
FROM agent_runs
WHERE tenant_id = $1 AND id = ANY($2)
