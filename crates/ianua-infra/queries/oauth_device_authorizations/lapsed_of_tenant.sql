-- One bounded batch of a tenant's expired pending requests, read through
-- its current shared or dedicated database route, earliest expiry first.
SELECT tenant_id, device_code_hash, user_code_sealed, client_id, scopes, status, approved_by,
       interval_secs, last_polled_at, created_at, expires_at
FROM oauth_device_authorizations
WHERE tenant_id = $1 AND status = 'pending' AND expires_at <= $2
ORDER BY expires_at
LIMIT $3
