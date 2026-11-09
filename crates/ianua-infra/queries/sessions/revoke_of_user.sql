-- Revokes every session a user of a tenant holds that is not revoked yet.
UPDATE sessions
SET status = 'revoked'
WHERE tenant_id = $1 AND user_id = $2 AND status <> 'revoked'
