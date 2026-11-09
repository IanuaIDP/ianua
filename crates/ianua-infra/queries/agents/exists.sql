-- Whether a tenant has an agent with the given id.
SELECT EXISTS (SELECT 1 FROM agents WHERE tenant_id = $1 AND id = $2) AS "exists!"
