-- The link of one purpose most recently issued to a member, used or not.
SELECT token_hash, org_user_id, sent_to, created_at, expires_at, consumed_at
FROM org_tokens
WHERE org_user_id = $1 AND purpose = $2
ORDER BY created_at DESC, token_hash DESC
LIMIT 1
