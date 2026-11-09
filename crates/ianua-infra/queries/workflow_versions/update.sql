-- Saves a change to one version already kept. Who drafted it and when it
-- was drafted never change.
UPDATE workflow_versions SET
    name = $4,
    graph = $5,
    trigger_kind = $6,
    trigger_schedule = $7,
    trigger_event = $8,
    trigger_service = $9,
    run_limit_secs = $10,
    status = $11,
    edited_by = $12,
    authors = $13,
    published_by = $14,
    hold = $15,
    updated_at = $16,
    description = $17,
    layout = $18,
    failure_alert = $19,
    trigger_change = $20
WHERE tenant_id = $1 AND workflow_id = $2 AND version = $3
