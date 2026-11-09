-- Closes the zone one tenant holds for one hostname, and with it every
-- record it answers with.
DELETE FROM dns_zones
WHERE tenant_id = $1 AND hostname = $2
