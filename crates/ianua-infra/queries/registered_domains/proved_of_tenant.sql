-- The proved domains of one tenant, read from the database of its own it
-- lives in, for the health check that asks DNS about them again.
SELECT tenant_id, id, domain, connection, verification_status, verified_at, failed_at,
       dns_challenge_token, tls_status, created_at
FROM registered_domains
WHERE tenant_id = $1 AND verification_status = 'verified'
ORDER BY id
