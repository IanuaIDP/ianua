-- Deletes the address change one organization member or operator asked
-- for.
DELETE FROM org_email_changes
WHERE principal_id = $1
