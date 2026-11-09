-- How many of a tenant's connections put people in the given group through
-- a group-mapping rule.
SELECT count(DISTINCT connection_id) AS "count!"
FROM connection_group_rules
WHERE tenant_id = $1 AND group_id = $2
