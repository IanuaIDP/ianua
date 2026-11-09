-- Every tenant's certificates running out before the given moment, each
-- with its tenant, soonest first.
SELECT id, tenant_id, domain_id, certificate_pem, private_key, issued_at, expires_at,
       source, issuer, subject_names
FROM domain_certificates
WHERE expires_at < $1
ORDER BY expires_at
