-- The proved domains of one tenant still waiting for a certificate, proved
-- before the cutoff, read from the database of its own it lives in.
SELECT tenant_id, id, domain, connection, verification_status, verified_at, failed_at,
       dns_challenge_token, tls_status, created_at
FROM registered_domains
WHERE tenant_id = $2
  AND verification_status = 'verified' AND tls_status = 'provisioning' AND verified_at < $1
ORDER BY verified_at
