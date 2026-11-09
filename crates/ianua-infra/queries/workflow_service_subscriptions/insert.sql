-- Keeps a registration made just now, and how its service's events reach
-- the platform.
INSERT INTO workflow_service_subscriptions
    (id, tenant_id, workflow_id, version, integration, trigger, secret_sealed, status, remote,
     lapses_at, route_key, label, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
