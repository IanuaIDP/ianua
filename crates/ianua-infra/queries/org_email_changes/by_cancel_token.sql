-- The address change the hash of the cancel link mailed to the old
-- address names.
SELECT principal_id, from_email, new_email, token_hash, cancel_token_hash,
       state, settled_at, created_at, expires_at
FROM org_email_changes
WHERE cancel_token_hash = $1
