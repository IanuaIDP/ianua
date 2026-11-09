-- The trusted device of a tenant with the given id.
SELECT id, user_id, secret_hash, device_name, last_user_agent, last_ip,
       status, last_seen_at, created_at
FROM trusted_devices
WHERE tenant_id = $1 AND id = $2
