-- Keeps a logout request a tenant sent a peer until it is answered. A
-- request kept again under the same ID replaces the one before.
INSERT INTO sent_logout_requests
    (tenant_id, id, peer, destination, name_id_format, name_id, session_index,
     sent_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (tenant_id, id) DO UPDATE SET
    peer = EXCLUDED.peer,
    destination = EXCLUDED.destination,
    name_id_format = EXCLUDED.name_id_format,
    name_id = EXCLUDED.name_id,
    session_index = EXCLUDED.session_index,
    sent_at = EXCLUDED.sent_at,
    expires_at = EXCLUDED.expires_at
