-- Removes the passkey with the given id.
DELETE FROM org_passkey_credentials
WHERE id = $1
