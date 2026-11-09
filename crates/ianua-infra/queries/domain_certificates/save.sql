-- Keeps a certificate for a domain one tenant claims: a new one is added
-- as the newest of its domain; a known one of the same tenant takes the
-- chain and the sealed key again. Its domain, tenant and place in the
-- order never change.
INSERT INTO domain_certificates
    (id, tenant_id, domain_id, certificate_pem, private_key, issued_at, expires_at,
     source, issuer, subject_names)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (id) DO UPDATE SET
    certificate_pem = EXCLUDED.certificate_pem,
    private_key = EXCLUDED.private_key
WHERE domain_certificates.tenant_id = EXCLUDED.tenant_id
