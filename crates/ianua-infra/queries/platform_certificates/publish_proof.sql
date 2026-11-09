-- Publish a short-lived DNS proof only for an active issuance lease.
INSERT INTO platform_dns_proofs (root, value, expires_at)
SELECT p.root, $2, now() + interval '10 minutes'
FROM platform_certificates p JOIN tenants t ON t.id = p.tenant_id
WHERE p.root = $1 AND p.lease_until > now() AND t.status IN ('active', 'provisioning')
    AND (NOT p.readable OR t.readable_address)
ON CONFLICT (root, value) DO UPDATE SET expires_at = EXCLUDED.expires_at
