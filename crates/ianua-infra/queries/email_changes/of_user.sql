-- The address change one user of one tenant asked for, if any.
SELECT user_id AS principal_id, from_email, new_email, token_hash, cancel_token_hash,
       state, settled_at, created_at, expires_at
FROM email_changes
WHERE tenant_id = $1 AND user_id = $2
