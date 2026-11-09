-- The organization session, in force or suspended, that holds a refresh
-- token, with its organization, member and end. A revoked or expired one is
-- left out.
SELECT id, organization_id, org_user_id, expires_at
FROM org_sessions
WHERE refresh_token_hash = $1 AND status <> 'revoked' AND expires_at > $2
