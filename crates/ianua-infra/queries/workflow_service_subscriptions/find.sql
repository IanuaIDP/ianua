-- Where the registration a delivery's address names is kept, in whichever
-- tenants the read may see.
SELECT tenant_id, id
FROM workflow_service_subscriptions
WHERE id = $1
