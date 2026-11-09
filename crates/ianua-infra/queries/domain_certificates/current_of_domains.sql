-- The certificate each of the given domains serves, whichever tenant
-- claims it: the newest saved for each, for the gateway.
SELECT DISTINCT ON (domain_id)
       id, tenant_id, domain_id, certificate_pem, private_key, issued_at, expires_at,
       source, issuer, subject_names
FROM domain_certificates
WHERE domain_id = ANY($1)
ORDER BY domain_id, saved_order DESC
