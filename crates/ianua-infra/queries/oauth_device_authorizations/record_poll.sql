-- Writes when one tenant's device last polled and its interval, leaving
-- where the authorization stands as stored, so a poll never undoes an
-- approval that landed meanwhile.
UPDATE oauth_device_authorizations
SET last_polled_at = $3, interval_secs = $4
WHERE tenant_id = $1 AND device_code_hash = $2
