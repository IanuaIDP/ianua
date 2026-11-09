-- The titles of a tenant's notifications with the given ids, for the audit trail to name them by.
SELECT id, title AS name
FROM tenant_notifications
WHERE tenant_id = $1 AND id = ANY($2)
