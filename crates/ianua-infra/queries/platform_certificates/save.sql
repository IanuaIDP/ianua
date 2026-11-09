-- Save the issued pair only while its tenant, consent and lease remain current.
UPDATE platform_certificates p
SET certificate_id = $1, certificate_pem = $4, private_key = $5, issued_at = $6, expires_at = $7,
    attempt_id = NULL, lease_until = NULL, next_attempt = now() + interval '1 day'
FROM tenants t
WHERE p.attempt_id = $1 AND p.tenant_id = $2 AND p.root = $3 AND p.lease_until > now()
    AND t.id = p.tenant_id AND t.status IN ('active', 'provisioning')
    AND (NOT p.readable OR t.readable_address)
