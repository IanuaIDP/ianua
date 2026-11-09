-- Every device one member trusted, revoked ones included, in the order
-- they were trusted.
SELECT id, org_user_id, secret_hash, device_name, last_user_agent, last_ip,
       status, last_seen_at, created_at
FROM org_trusted_devices
WHERE org_user_id = $1
ORDER BY created_at, id
