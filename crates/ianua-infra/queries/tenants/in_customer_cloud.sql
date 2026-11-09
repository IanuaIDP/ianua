-- How many tenants of an organization, not deleted, live in the customer's
-- own account at the given cloud.
SELECT count(*) AS "count!"
FROM tenants
WHERE organization_id = $1 AND customer_cloud = $2 AND status <> 'deleted'
