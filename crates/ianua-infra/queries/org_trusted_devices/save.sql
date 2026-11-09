-- Keeps a member's trusted device: a new one is added, a known one takes
-- the new values. Its member and when it was trusted never change. A
-- revoked device takes nothing new, so a sign-in that read it before the
-- revocation never trusts it again.
INSERT INTO org_trusted_devices
    (id, org_user_id, secret_hash, device_name, last_user_agent, last_ip,
     status, last_seen_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (id) DO UPDATE SET
    secret_hash = EXCLUDED.secret_hash,
    device_name = EXCLUDED.device_name,
    last_user_agent = EXCLUDED.last_user_agent,
    last_ip = EXCLUDED.last_ip,
    status = EXCLUDED.status,
    last_seen_at = EXCLUDED.last_seen_at
WHERE org_trusted_devices.org_user_id = EXCLUDED.org_user_id
    AND org_trusted_devices.status <> 'revoked'
