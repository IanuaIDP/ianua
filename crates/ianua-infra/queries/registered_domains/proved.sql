-- The proved domains of every tenant in this database, for the health
-- check that asks DNS about them again.
SELECT tenant_id, id, domain, connection, verification_status, verified_at, failed_at,
       dns_challenge_token, tls_status, created_at
FROM registered_domains
WHERE verification_status = 'verified'
ORDER BY tenant_id, id
