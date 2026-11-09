-- Moves a registration kept waiting to what its service answered, and how
-- its events reach the platform. Its secret is left as it stands, since the
-- service may have handed over its own while the call was open.
UPDATE workflow_service_subscriptions SET
    status = $3,
    remote = $4,
    lapses_at = $5,
    route_key = $6,
    updated_at = $7
WHERE tenant_id = $1 AND id = $2 AND status = 'registering'
