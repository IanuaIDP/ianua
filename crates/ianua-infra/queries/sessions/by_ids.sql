-- The sessions of a tenant with the given ids.
SELECT id, user_id, refresh_token_hash, parent_id, ip_address, user_agent,
       auth_method, factor, owed, status, app_service_id,
       signed_in_at, created_at, last_active_at, expires_at, kept_through, signed_in_from,
       last_used_network, last_used_latitude, last_used_longitude, last_used_country, last_used_at
FROM sessions
WHERE tenant_id = $1 AND id = ANY($2)
