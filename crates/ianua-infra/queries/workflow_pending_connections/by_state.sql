-- Where the connection whose state digest a service's answer brought back
-- was begun, in whichever tenants the read may see.
SELECT tenant_id, id
FROM workflow_pending_connections
WHERE state_hash = $1
