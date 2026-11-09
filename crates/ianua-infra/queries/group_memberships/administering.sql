-- The memberships of tenant users still in force at the given time in any
-- group of a tenant at or below one carrying any of the given roles.
WITH RECURSIVE reached (id) AS (
    SELECT gr.group_id
    FROM group_roles gr
    WHERE gr.tenant_id = $1 AND gr.role_id = ANY($2)
    UNION
    SELECT below.id
    FROM groups below
    JOIN reached ON below.parent_id = reached.id
    WHERE below.tenant_id = $1
)
SELECT m.group_id, m.principal_kind, m.principal_id, m.joined_at, m.expires_at
FROM group_memberships m
WHERE m.tenant_id = $1 AND m.group_id IN (SELECT id FROM reached)
  AND m.principal_kind = 'user' AND (m.expires_at IS NULL OR m.expires_at > $3)
ORDER BY m.joined_at, m.group_id, m.principal_id
