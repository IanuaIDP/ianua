-- Deletes the address change one user of one tenant asked for.
DELETE FROM email_changes
WHERE tenant_id = $1 AND user_id = $2
