-- The group of a tenant with the given name, with the roles it carries.
SELECT g.id, g.name, g.origin, g.parent_id,
       ARRAY(
           SELECT gr.role_id
           FROM group_roles gr
           WHERE gr.tenant_id = g.tenant_id AND gr.group_id = g.id
           ORDER BY gr.position
       ) AS "role_ids!",
       g.created_at, g.updated_at
FROM groups g
WHERE g.tenant_id = $1 AND g.name = $2
