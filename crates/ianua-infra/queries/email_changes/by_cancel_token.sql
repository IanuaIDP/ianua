-- The address change of one tenant the hash of the cancel link mailed to
-- the old address names.
SELECT user_id AS principal_id, from_email, new_email, token_hash, cancel_token_hash,
       state, settled_at, created_at, expires_at
FROM email_changes
WHERE tenant_id = $1 AND cancel_token_hash = $2
