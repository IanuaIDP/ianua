-- How many groups of a tenant carry the given role.
SELECT count(*) AS "count!"
FROM group_roles
WHERE tenant_id = $1 AND role_id = $2
