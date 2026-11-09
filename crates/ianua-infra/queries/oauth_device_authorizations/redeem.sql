-- Marks one tenant's device authorization redeemed, only while it is still
-- approved and unexpired at the given time: of two polls arriving
-- together, only one changes the row.
UPDATE oauth_device_authorizations
SET status = 'redeemed'
WHERE tenant_id = $1 AND device_code_hash = $2 AND status = 'approved' AND expires_at > $3
