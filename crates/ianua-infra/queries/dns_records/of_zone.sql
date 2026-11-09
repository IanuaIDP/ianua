-- Every record set of the zone one tenant holds for one hostname.
SELECT hostname, name, kind, ttl, record_values
FROM dns_records
WHERE tenant_id = $1 AND hostname = $2
