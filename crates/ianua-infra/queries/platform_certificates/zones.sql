-- Read public DNS data and live proofs for currently served tenant roots.
SELECT p.root, p.tenant_id, p.nameservers, p.address, p.changed_at,
    ARRAY(SELECT d.value FROM platform_dns_proofs d WHERE d.root = p.root AND d.expires_at > now()
          ORDER BY d.value LIMIT 16) AS "proofs!"
FROM platform_certificates p JOIN tenants t ON t.id = p.tenant_id
WHERE t.status IN ('active', 'provisioning') AND (NOT p.readable OR t.readable_address)
ORDER BY p.root LIMIT 100000
