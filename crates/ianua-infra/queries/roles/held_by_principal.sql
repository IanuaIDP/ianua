-- Every role of a tenant one principal holds: given straight to them, or,
-- for a tenant user, carried by a group they are in or a group above one,
-- each role once. A grant or a membership whose time ran out at the given
-- moment confers nothing, though the sweep has not removed it yet.
WITH RECURSIVE held_groups (id) AS (
    SELECT m.group_id
    FROM group_memberships m
    WHERE m.tenant_id = $1 AND $2 = 'user'
      AND m.principal_kind = 'user' AND m.principal_id = $3
      AND (m.expires_at IS NULL OR m.expires_at > $4)
    UNION
    SELECT g.parent_id
    FROM groups g
    JOIN held_groups h ON g.id = h.id
    WHERE g.tenant_id = $1 AND g.parent_id IS NOT NULL
)
SELECT r.id, r.name, r.system_permissions, r.custom_permissions, r.is_default,
       r.created_at, r.updated_at
FROM roles r
WHERE r.tenant_id = $1
  AND (
      r.id IN (
          SELECT a.role_id
          FROM role_assignments a
          WHERE a.tenant_id = $1 AND a.principal_kind = $2 AND a.principal_id = $3
            AND (a.expires_at IS NULL OR a.expires_at > $4)
      )
      OR r.id IN (
          SELECT gr.role_id
          FROM group_roles gr
          WHERE gr.tenant_id = $1 AND gr.group_id IN (SELECT id FROM held_groups)
      )
  )
ORDER BY r.created_at, r.id
