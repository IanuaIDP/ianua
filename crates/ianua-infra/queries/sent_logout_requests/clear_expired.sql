-- Forgets a tenant's sent logout requests whose answer stopped being
-- taken by the given time.
DELETE FROM sent_logout_requests
WHERE tenant_id = $1 AND expires_at <= $2
