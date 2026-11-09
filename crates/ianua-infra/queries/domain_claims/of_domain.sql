-- The claim one registration holds, with the tenant holding it.
SELECT hostname, tenant_id, domain_id
FROM domain_claims
WHERE domain_id = $1
