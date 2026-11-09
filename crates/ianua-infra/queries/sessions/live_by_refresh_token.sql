-- The session, in force or suspended, that holds a refresh token, with its
-- tenant, user and end, for a bearer whose tenant is not known yet. A revoked or
-- expired one is left out; two answers mean a broken digest and are
-- refused by the caller.
SELECT id, tenant_id, user_id, expires_at
FROM sessions
WHERE refresh_token_hash = $1 AND status <> 'revoked' AND expires_at > $2
LIMIT 2
