-- How many principals were given one role of a tenant straight.
SELECT count(*) AS "count!"
FROM role_assignments
WHERE tenant_id = $1 AND role_id = $2
