-- Keeps a session: a new one is added, a known one of the same tenant and
-- user takes the new values. Its tenant, user, refresh token, parent, way
-- in and the times it was signed in and made never change. The device it
-- was signed in from is set once, at the sign-in or when the sign-in's own
-- second-factor step remembers the device, and a copy read before then
-- never clears it. A revoked session takes nothing new, so a save of a
-- copy read before the revocation never makes it live again.
INSERT INTO sessions
    (id, tenant_id, user_id, refresh_token_hash, parent_id, ip_address, user_agent,
     auth_method, factor, owed, status, app_service_id,
     signed_in_at, created_at, last_active_at, expires_at, kept_through, signed_in_from,
     last_used_network, last_used_latitude, last_used_longitude, last_used_country, last_used_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
        $19, $20, $21, $22, $23)
ON CONFLICT (id) DO UPDATE SET
    ip_address = EXCLUDED.ip_address,
    user_agent = EXCLUDED.user_agent,
    factor = EXCLUDED.factor,
    owed = EXCLUDED.owed,
    status = EXCLUDED.status,
    app_service_id = EXCLUDED.app_service_id,
    last_active_at = EXCLUDED.last_active_at,
    expires_at = EXCLUDED.expires_at,
    kept_through = EXCLUDED.kept_through,
    signed_in_from = COALESCE(sessions.signed_in_from, EXCLUDED.signed_in_from),
    last_used_network = EXCLUDED.last_used_network,
    last_used_latitude = EXCLUDED.last_used_latitude,
    last_used_longitude = EXCLUDED.last_used_longitude,
    last_used_country = EXCLUDED.last_used_country,
    last_used_at = EXCLUDED.last_used_at
WHERE sessions.tenant_id = EXCLUDED.tenant_id AND sessions.user_id = EXCLUDED.user_id
    AND sessions.status <> 'revoked'
