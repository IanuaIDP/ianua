-- Revokes every session of a tenant that is not revoked yet.
UPDATE sessions
SET status = 'revoked'
WHERE tenant_id = $1 AND status <> 'revoked'
