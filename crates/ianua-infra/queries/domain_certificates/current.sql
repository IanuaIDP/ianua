-- The certificate one tenant's domain serves: the newest saved for it.
SELECT id, tenant_id, domain_id, certificate_pem, private_key, issued_at, expires_at,
       source, issuer, subject_names
FROM domain_certificates
WHERE tenant_id = $1 AND domain_id = $2
ORDER BY saved_order DESC
LIMIT 1
