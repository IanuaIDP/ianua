-- Revokes every session of one member not revoked yet, suspended ones
-- included.
UPDATE org_sessions
SET status = 'revoked'
WHERE org_user_id = $1 AND status <> 'revoked'
