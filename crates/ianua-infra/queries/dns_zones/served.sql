-- The zones the nameservers serve, whichever tenant holds them: those whose
-- registration proved the name, with when what each answers last changed.
-- At most $1, in one fixed order, so a load past the reader's cap keeps
-- the same zones every time.
SELECT z.hostname, z.tenant_id, z.nameservers, z.changed_at, c.verified
FROM dns_zones z
JOIN domain_claims c ON c.tenant_id = z.tenant_id AND c.hostname = z.hostname
WHERE c.verified
ORDER BY z.tenant_id, z.hostname
LIMIT $1
