-- Every device a user of a tenant trusted, revoked ones included, in the
-- order they were trusted.
SELECT id, user_id, secret_hash, device_name, last_user_agent, last_ip,
       status, last_seen_at, created_at
FROM trusted_devices
WHERE tenant_id = $1 AND user_id = $2
ORDER BY created_at, id
