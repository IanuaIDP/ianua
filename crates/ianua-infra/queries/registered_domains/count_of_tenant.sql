-- How many domains a tenant registered against its plan, proved or not,
-- since a registration claims its name either way.
SELECT count(*) AS "count!"
FROM registered_domains
WHERE tenant_id = $1
