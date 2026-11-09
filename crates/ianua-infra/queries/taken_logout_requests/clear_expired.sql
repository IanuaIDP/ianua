-- Forgets a tenant's taken logout requests that expired by the given time:
-- none of them is taken any more anyway.
DELETE FROM taken_logout_requests
WHERE tenant_id = $1 AND expires_at <= $2
