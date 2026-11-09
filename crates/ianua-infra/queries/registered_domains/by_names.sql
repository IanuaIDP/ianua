-- The registrations proving a requested batch of names for one tenant.
SELECT tenant_id, id, domain, connection, verification_status, verified_at, failed_at,
       dns_challenge_token, tls_status, created_at
FROM registered_domains
WHERE tenant_id = $1 AND domain = ANY($2::text[])
