-- Reconcile the desired roots in bulk, preserving existing leases and certificates.
INSERT INTO platform_certificates (root, tenant_id, readable, nameservers, address)
SELECT wanted.root, wanted.tenant_id, wanted.readable, $4, $5
FROM unnest($1::text[], $2::uuid[], $3::boolean[]) AS wanted(root, tenant_id, readable)
JOIN tenants t ON t.id = wanted.tenant_id
WHERE t.status IN ('active', 'provisioning') AND (NOT wanted.readable OR t.readable_address)
ON CONFLICT (root) DO UPDATE SET nameservers = EXCLUDED.nameservers, address = EXCLUDED.address
WHERE platform_certificates.tenant_id = EXCLUDED.tenant_id
    AND platform_certificates.readable = EXCLUDED.readable
