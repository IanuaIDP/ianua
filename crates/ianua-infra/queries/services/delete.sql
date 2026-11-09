-- Deletes one service of one tenant, with the sign-in hosts it holds. A
-- route forwarding to it, or a service accepting its sign-in, refuses it.
DELETE FROM services
WHERE tenant_id = $1 AND id = $2
