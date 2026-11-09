-- How many federation connections a tenant holds against its plan,
-- disabled ones too.
SELECT count(*) AS "count!"
FROM federation_connections
WHERE tenant_id = $1
