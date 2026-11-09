-- Adds an evaluation just started.
INSERT INTO evaluations
    (id, tenant_id, workflow_id, version, revision, cases, outcomes, state, started_by,
     deadline, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
