-- Keeps a registered domain: a new one is added, a known one of the same
-- tenant takes its new proof and certificate status. Its name, how it is
-- connected, its token and when it was registered never change, and
-- neither does when the sweep last checked it.
INSERT INTO registered_domains
    (tenant_id, id, domain, connection, verification_status, verified_at, failed_at,
     dns_challenge_token, tls_status, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (tenant_id, id) DO UPDATE SET
    verification_status = EXCLUDED.verification_status,
    verified_at = EXCLUDED.verified_at,
    failed_at = EXCLUDED.failed_at,
    tls_status = EXCLUDED.tls_status
