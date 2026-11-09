-- Keeps a run without its steps: a new one is added, a known one of the
-- same tenant takes its new standing. Its tenant, its agent, its provider,
-- its goal, who started it, the check its answers are held to and when
-- never change.
INSERT INTO agent_runs
    (id, tenant_id, agent_id, provider_id, goal, purpose, granted_tools, approval_classes,
     approval, delegation_id, max_steps, spend_limit_micros, input_tokens, output_tokens,
     spent_micros, started_by_kind, started_by_id, started_by_person, exposure, chain_depth,
     status, pending_call, created_at, updated_at, spend_check, spend_check_micros,
     check_version_id, check_tries)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
        $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)
ON CONFLICT (id) DO UPDATE SET
    purpose = EXCLUDED.purpose,
    granted_tools = EXCLUDED.granted_tools,
    approval_classes = EXCLUDED.approval_classes,
    approval = EXCLUDED.approval,
    delegation_id = EXCLUDED.delegation_id,
    max_steps = EXCLUDED.max_steps,
    spend_limit_micros = EXCLUDED.spend_limit_micros,
    input_tokens = EXCLUDED.input_tokens,
    output_tokens = EXCLUDED.output_tokens,
    spent_micros = EXCLUDED.spent_micros,
    exposure = EXCLUDED.exposure,
    chain_depth = EXCLUDED.chain_depth,
    status = EXCLUDED.status,
    pending_call = EXCLUDED.pending_call,
    updated_at = EXCLUDED.updated_at,
    spend_check = EXCLUDED.spend_check,
    spend_check_micros = EXCLUDED.spend_check_micros
WHERE agent_runs.tenant_id = EXCLUDED.tenant_id
