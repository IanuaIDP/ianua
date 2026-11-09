-- The device authorization of one tenant whose user code has the given
-- keyed hash.
SELECT tenant_id, device_code_hash, user_code_sealed, client_id, scopes, status, approved_by,
       interval_secs, last_polled_at, created_at, expires_at
FROM oauth_device_authorizations
WHERE tenant_id = $1 AND user_code_hash = $2
