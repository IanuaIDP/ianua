-- The address change of one tenant the hash of its confirmation link
-- names.
SELECT user_id AS principal_id, from_email, new_email, token_hash, cancel_token_hash,
       state, settled_at, created_at, expires_at
FROM email_changes
WHERE tenant_id = $1 AND token_hash = $2
