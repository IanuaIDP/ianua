-- The proved domains of every tenant in this database still waiting for a
-- certificate, proved before the cutoff, longest waiting first.
SELECT tenant_id, id, domain, connection, verification_status, verified_at, failed_at,
       dns_challenge_token, tls_status, created_at
FROM registered_domains
WHERE verification_status = 'verified' AND tls_status = 'provisioning' AND verified_at < $1
ORDER BY verified_at
