-- The registrations of one workflow of one tenant not yet removed, of any
-- version, oldest first.
SELECT id, workflow_id, version, trigger, secret_sealed, status, remote, lapses_at, label,
    created_at, updated_at
FROM workflow_service_subscriptions
WHERE tenant_id = $1 AND workflow_id = $2 AND status <> 'removed'
ORDER BY created_at, id
