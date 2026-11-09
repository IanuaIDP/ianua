-- The groups of a tenant with the given ids and every group above them,
-- each once, with the roles it carries.
WITH RECURSIVE lineage (id) AS (
    SELECT start.id
    FROM groups start
    WHERE start.tenant_id = $1 AND start.id = ANY($2)
    UNION
    SELECT above.parent_id
    FROM groups above
    JOIN lineage ON above.id = lineage.id
    WHERE above.tenant_id = $1 AND above.parent_id IS NOT NULL
)
SELECT g.id, g.name, g.origin, g.parent_id,
       ARRAY(
           SELECT gr.role_id
           FROM group_roles gr
           WHERE gr.tenant_id = g.tenant_id AND gr.group_id = g.id
           ORDER BY gr.position
       ) AS "role_ids!",
       g.created_at, g.updated_at
FROM groups g
WHERE g.tenant_id = $1 AND g.id IN (SELECT id FROM lineage)
ORDER BY g.created_at, g.id
