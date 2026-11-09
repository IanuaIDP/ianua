-- The registered domains of one tenant with the given ids.
SELECT tenant_id, id, domain, connection, verification_status, verified_at, failed_at,
       dns_challenge_token, tls_status, created_at
FROM registered_domains
WHERE tenant_id = $1 AND id = ANY($2)
