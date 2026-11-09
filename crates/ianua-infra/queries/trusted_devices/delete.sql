-- Removes the trusted device of a tenant with the given id.
DELETE FROM trusted_devices
WHERE tenant_id = $1 AND id = $2
