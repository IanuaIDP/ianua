-- Serve valid pairs only for tenants that still want their addresses.
SELECT p.certificate_id AS "id!", p.tenant_id, p.root, p.certificate_pem AS "certificate_pem!",
    p.private_key AS "private_key!", p.issued_at AS "issued_at!", p.expires_at AS "expires_at!"
FROM platform_certificates p JOIN tenants t ON t.id = p.tenant_id
WHERE p.certificate_id IS NOT NULL AND p.issued_at <= now() AND p.expires_at > now()
    AND t.status IN ('active', 'provisioning') AND (NOT p.readable OR t.readable_address)
ORDER BY p.root LIMIT 100000
