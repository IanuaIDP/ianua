-- The domains of one tenant that serve, for the gateway: proved, and with
-- an active certificate where one is needed, as
-- `RegisteredDomain::is_active` holds them.
SELECT tenant_id, id, domain, tls_status
FROM registered_domains
WHERE tenant_id = $1 AND verification_status = 'verified'
  AND tls_status IN ('not_required', 'active')
ORDER BY id
