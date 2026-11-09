-- The address change the hash of its confirmation link names.
SELECT principal_id, from_email, new_email, token_hash, cancel_token_hash,
       state, settled_at, created_at, expires_at
FROM org_email_changes
WHERE token_hash = $1
