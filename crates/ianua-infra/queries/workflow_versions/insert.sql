-- Keeps a version drafted just now. A version of the workflow with its
-- number already kept refuses it.
INSERT INTO workflow_versions
    (tenant_id, workflow_id, version, name, graph, trigger_kind, trigger_schedule,
     trigger_event, trigger_service, run_limit_secs, status, created_by, edited_by, authors,
     published_by, hold, created_at, updated_at, description, layout, failure_alert,
     trigger_change)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
    $20, $21, $22)
