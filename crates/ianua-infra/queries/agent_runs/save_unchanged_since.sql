-- Gives a stored run of the tenant its new standing, only while it is
-- still at the version the caller read, and answers the version it is
-- stored at now. No row comes back when the run changed since, or is gone.
UPDATE agent_runs SET
    purpose = $4,
    granted_tools = $5,
    approval_classes = $6,
    approval = $7,
    delegation_id = $8,
    max_steps = $9,
    spend_limit_micros = $10,
    input_tokens = $11,
    output_tokens = $12,
    spent_micros = $13,
    exposure = $14,
    chain_depth = $15,
    status = $16,
    pending_call = $17,
    updated_at = $18,
    spend_check = $19,
    spend_check_micros = $20
WHERE tenant_id = $1 AND id = $2 AND updated_at = $3
RETURNING updated_at
