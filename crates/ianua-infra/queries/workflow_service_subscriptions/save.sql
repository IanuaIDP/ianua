-- Saves a change to one registration already kept: where it stands and the
-- service's side of it. What it registers for, its secret and how its
-- events reach the platform never change.
UPDATE workflow_service_subscriptions SET
    status = $3,
    remote = $4,
    lapses_at = $5,
    updated_at = $6
WHERE tenant_id = $1 AND id = $2
