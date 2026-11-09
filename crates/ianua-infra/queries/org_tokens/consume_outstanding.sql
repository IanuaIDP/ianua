-- Spends, at the given time, every link of one purpose a member holds that
-- is still unused and in date, so a link sent later supersedes them.
UPDATE org_tokens
SET consumed_at = $3
WHERE org_user_id = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > $3
