-- One device, when it is the given member's: another member's device
-- reads as absent.
SELECT id, org_user_id, secret_hash, device_name, last_user_agent, last_ip,
       status, last_seen_at, created_at
FROM org_trusted_devices
WHERE id = $2 AND org_user_id = $1
