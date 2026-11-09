-- Spends, at the given moment, every link of one purpose a user of a tenant
-- holds that is unused and still in date.
UPDATE mailed_links
SET used_at = $4
WHERE tenant_id = $1 AND purpose = $2 AND user_id = $3
  AND used_at IS NULL AND expires_at > $4 AND created_at <= $4
