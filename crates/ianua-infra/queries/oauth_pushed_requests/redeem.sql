-- Marks one tenant's pushed request used, only while it is still unused:
-- of two browsers arriving with one request_uri, only one changes the row.
UPDATE oauth_pushed_requests
SET used_at = $3
WHERE tenant_id = $1 AND id = $2 AND used_at IS NULL
