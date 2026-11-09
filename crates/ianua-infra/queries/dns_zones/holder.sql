-- The tenant holding the zone of one hostname, and the nameservers it
-- answers with.
SELECT tenant_id, nameservers
FROM dns_zones
WHERE hostname = $1
