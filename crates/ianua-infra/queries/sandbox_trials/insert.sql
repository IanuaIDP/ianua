-- Adds a trial just started.
INSERT INTO sandbox_trials
    (id, tenant_id, sandbox_id, version_id, input, state, output, failure, failure_detail,
     started_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
