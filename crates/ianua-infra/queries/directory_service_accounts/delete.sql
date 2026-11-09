-- Removes a directory service account of the tenant; one already gone is
-- passed over.
DELETE FROM directory_service_accounts
WHERE tenant_id = $1 AND id = $2
