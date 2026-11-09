-- How many principals were given each of the given roles of a tenant
-- straight. A role nobody holds is left out.
SELECT role_id, count(*) AS "count!"
FROM role_assignments
WHERE tenant_id = $1 AND role_id = ANY($2)
GROUP BY role_id
