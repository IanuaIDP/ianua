-- How many API keys a tenant holds against its plan. A revoked key is
-- deleted, so every row is one in force or waiting for the expiry sweep.
SELECT count(*) AS "count!"
FROM api_keys
WHERE tenant_id = $1
