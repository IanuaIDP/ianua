-- Revokes every session of one organization's members not revoked yet,
-- suspended ones included.
UPDATE org_sessions
SET status = 'revoked'
WHERE organization_id = $1 AND status <> 'revoked'
