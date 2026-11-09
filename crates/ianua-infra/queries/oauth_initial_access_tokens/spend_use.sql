-- Writes the uses one tenant's initial access token has left, one fewer,
-- only while it is unrevoked and has exactly one more: of two
-- registrations spending its last use together, only one is admitted.
UPDATE oauth_initial_access_tokens
SET uses_left = $3
WHERE tenant_id = $1 AND id = $2 AND uses_left = $3 + 1 AND revoked_at IS NULL
