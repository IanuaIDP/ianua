-- A member's sessions still in force at the given time: active, not
-- expired, and owing nothing more to finish signing in. Newest first.
SELECT id, organization_id, org_user_id, working_tenant, refresh_token_hash,
       auth_method, factor, owed, ip_address, user_agent, status, kept_through,
       created_at, last_active_at, expires_at
FROM org_sessions
WHERE org_user_id = $1
  AND status = 'active'
  AND expires_at > $2
  AND owed = 'not_owed'
ORDER BY created_at DESC, id DESC
