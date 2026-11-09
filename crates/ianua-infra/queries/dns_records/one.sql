-- The one record set of the zone one tenant holds for one hostname that
-- answers one name and type, if the zone has it.
SELECT hostname, name, kind, ttl, record_values
FROM dns_records
WHERE tenant_id = $1 AND hostname = $2 AND name = $3 AND kind = $4
