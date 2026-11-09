-- How many of a tenant's connections hand out the given role: as the role
-- new accounts are given, or through a group-mapping rule.
SELECT count(*) AS "count!"
FROM federation_connections c
WHERE c.tenant_id = $1
  AND (c.jit_default_role_id = $2
       OR EXISTS (SELECT 1
                  FROM connection_group_rules r
                  WHERE r.tenant_id = c.tenant_id AND r.connection_id = c.id
                    AND r.role_id = $2))
