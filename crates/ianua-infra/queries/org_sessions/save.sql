-- Keeps a member's session: a new one is added, a known one takes the new
-- values. Its member, organization and creation time never change. A
-- revoked session takes nothing new, so a save of a copy read before the
-- revocation never makes it live again.
INSERT INTO org_sessions
    (id, organization_id, org_user_id, working_tenant, refresh_token_hash,
     auth_method, factor, owed, ip_address, user_agent, status, kept_through,
     created_at, last_active_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT (id) DO UPDATE SET
    working_tenant = EXCLUDED.working_tenant,
    refresh_token_hash = EXCLUDED.refresh_token_hash,
    auth_method = EXCLUDED.auth_method,
    factor = EXCLUDED.factor,
    owed = EXCLUDED.owed,
    ip_address = EXCLUDED.ip_address,
    user_agent = EXCLUDED.user_agent,
    status = EXCLUDED.status,
    kept_through = EXCLUDED.kept_through,
    last_active_at = EXCLUDED.last_active_at,
    expires_at = EXCLUDED.expires_at
WHERE org_sessions.status <> 'revoked'
