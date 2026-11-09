-- Forgets one registration, only if it is still waiting on its service.
DELETE FROM workflow_service_subscriptions
WHERE tenant_id = $1 AND id = $2 AND status = 'registering'
