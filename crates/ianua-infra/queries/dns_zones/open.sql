-- Opens the zone of a hostname one tenant claims, answering with the
-- nameservers given. A zone already open is left as it is, and a name the
-- tenant does not claim opens nothing.
INSERT INTO dns_zones (hostname, tenant_id, nameservers, changed_at)
SELECT hostname, tenant_id, $3::text[], $4::timestamptz
FROM domain_claims
WHERE tenant_id = $1 AND hostname = $2
ON CONFLICT (hostname) DO NOTHING
