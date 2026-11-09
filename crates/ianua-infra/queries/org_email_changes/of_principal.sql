-- The address change one organization member or operator asked for, if
-- any.
SELECT principal_id, from_email, new_email, token_hash, cancel_token_hash,
       state, settled_at, created_at, expires_at
FROM org_email_changes
WHERE principal_id = $1
