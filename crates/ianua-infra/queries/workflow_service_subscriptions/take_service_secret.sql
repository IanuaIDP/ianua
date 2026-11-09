-- Replaces the secret of a waiting registration with the one its service
-- chose. Only the first is taken, in one statement, so two arriving at once
-- leave one.
UPDATE workflow_service_subscriptions SET
    secret_sealed = $3,
    secret_given_at = $4
WHERE tenant_id = $1 AND id = $2 AND status = 'registering' AND secret_given_at IS NULL
