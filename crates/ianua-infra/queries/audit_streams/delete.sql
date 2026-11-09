-- Removes the tenant's audit stream with the given id.
DELETE FROM audit_streams
WHERE tenant_id = $1 AND id = $2
