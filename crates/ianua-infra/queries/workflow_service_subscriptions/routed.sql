-- The live registrations of one integration that its app's events name by
-- one key, in whichever tenants the read may see.
SELECT tenant_id, id
FROM workflow_service_subscriptions
WHERE integration = $1 AND route_key = $2 AND status = 'live'
