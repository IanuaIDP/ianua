-- How many attributes a tenant declared, archived ones too.
SELECT count(*) AS "count!"
FROM user_attribute_definitions
WHERE tenant_id = $1
