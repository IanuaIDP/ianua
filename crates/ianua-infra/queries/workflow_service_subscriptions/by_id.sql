-- One registration of one tenant, by the id its address names.
SELECT id, workflow_id, version, trigger, secret_sealed, status, remote, lapses_at, label,
    created_at, updated_at
FROM workflow_service_subscriptions
WHERE tenant_id = $1 AND id = $2
