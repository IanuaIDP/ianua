-- Up to a page of the registrations waiting on their service since before a
-- moment, the oldest first, in whichever tenants the read may see.
SELECT tenant_id, id
FROM workflow_service_subscriptions
WHERE status = 'registering' AND created_at < $1
ORDER BY created_at, id
LIMIT $2
