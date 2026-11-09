-- Every session a user of a tenant holds or held that no later session
-- replaced by a refresh, open or ended, newest sign-in first.
SELECT s.id, s.user_id, s.refresh_token_hash, s.parent_id, s.ip_address, s.user_agent,
       s.auth_method, s.factor, s.owed, s.status, s.app_service_id,
       s.signed_in_at, s.created_at, s.last_active_at, s.expires_at, s.kept_through,
       s.signed_in_from, s.last_used_network, s.last_used_latitude, s.last_used_longitude,
       s.last_used_country, s.last_used_at
FROM sessions s
WHERE s.tenant_id = $1 AND s.user_id = $2
  AND NOT EXISTS (
      SELECT 1 FROM sessions c WHERE c.tenant_id = s.tenant_id AND c.parent_id = s.id
  )
ORDER BY s.created_at DESC, s.id DESC
