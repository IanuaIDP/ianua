-- The mailed link of the given purpose with the given digest.
SELECT token_hash, org_user_id, sent_to, created_at, expires_at, consumed_at
FROM org_tokens
WHERE token_hash = $1 AND purpose = $2
