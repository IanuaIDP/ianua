-- Removes the passkey of a tenant with the given id.
DELETE FROM passkey_credentials
WHERE tenant_id = $1 AND id = $2
