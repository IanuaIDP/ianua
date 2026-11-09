-- The claim on one hostname, with the tenant holding it.
SELECT hostname, tenant_id, domain_id
FROM domain_claims
WHERE hostname = $1
