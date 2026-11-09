-- Releases the hostname one registration of one tenant claims, and with it
-- the certificates that serve it.
DELETE FROM domain_claims
WHERE tenant_id = $1 AND domain_id = $2
