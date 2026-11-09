-- Removes the tenant's records up to and with the given one, as only the
-- audit purge's role may.
DELETE FROM audit_records
WHERE tenant_id = $1 AND seq <= $2
