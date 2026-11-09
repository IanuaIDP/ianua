-- Every record set of the given zones, each named by the tenant holding it
-- and its hostname, whichever tenant that is: what the nameservers serve.
SELECT hostname, name, kind, ttl, record_values
FROM dns_records
WHERE (tenant_id, hostname) IN (
    SELECT served.tenant_id, served.hostname
    FROM unnest($1::uuid[], $2::text[]) AS served (tenant_id, hostname)
)
