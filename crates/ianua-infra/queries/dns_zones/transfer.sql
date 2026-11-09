-- Moves the zone of one hostname from one tenant to another, with every
-- record it answers with. A zone the giving tenant does not hold is left as
-- it is.
UPDATE dns_zones
SET tenant_id = $2
WHERE tenant_id = $1 AND hostname = $3
