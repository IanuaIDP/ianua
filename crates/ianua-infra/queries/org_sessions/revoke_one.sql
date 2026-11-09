-- Revokes one member's session, unless it already was.
UPDATE org_sessions
SET status = 'revoked'
WHERE id = $1 AND status <> 'revoked'
