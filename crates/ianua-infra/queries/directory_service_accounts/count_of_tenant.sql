-- How many directory service accounts a tenant holds against its plan,
-- disabled ones too.
SELECT count(*) AS "count!"
FROM directory_service_accounts
WHERE tenant_id = $1
