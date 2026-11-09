-- One latest stored-pending invitation per requested user in one tenant.
SELECT i.id, i.user_id, i.email, i.invited_by, i.role_id, i.token_hash, i.status,
       i.accepted_at, i.message, i.expires_at, i.created_at
FROM (SELECT DISTINCT unnest($2::uuid[]) AS user_id) requested
JOIN LATERAL (
    SELECT id FROM invitations
    WHERE tenant_id = $1 AND user_id = requested.user_id AND status = 'pending'
    ORDER BY created_at DESC, id DESC
    LIMIT 1
) latest ON true
JOIN invitations i ON i.tenant_id = $1 AND i.id = latest.id
