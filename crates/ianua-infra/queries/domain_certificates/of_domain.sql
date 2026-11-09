-- The certificate a domain serves, whichever tenant claims it: the newest
-- saved for it.
SELECT id, tenant_id, domain_id, certificate_pem, private_key, issued_at, expires_at,
       source, issuer, subject_names
FROM domain_certificates
WHERE domain_id = $1
ORDER BY saved_order DESC
LIMIT 1
