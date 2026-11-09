-- Removes a tenant's sessions over by the given moment: those that expired
-- before it, and those revoked and last used before it that no later
-- session replaced by a refresh. A session in force expires later and is
-- never revoked, so it stays.
DELETE FROM sessions s
WHERE s.tenant_id = $1
  AND (
      s.expires_at < $2
      OR (
          s.status = 'revoked'
          AND s.last_active_at < $2
          AND NOT EXISTS (
              SELECT 1 FROM sessions c WHERE c.tenant_id = s.tenant_id AND c.parent_id = s.id
          )
      )
  )
