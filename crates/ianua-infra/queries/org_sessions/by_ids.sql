-- The members' sessions with the given ids.
SELECT id, organization_id, org_user_id, working_tenant, refresh_token_hash,
       auth_method, factor, owed, ip_address, user_agent, status, kept_through,
       created_at, last_active_at, expires_at
FROM org_sessions
WHERE id = ANY($1)
