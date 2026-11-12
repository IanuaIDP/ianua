-- Moves a registration's claim on a hostname to the tenant now saving it,
-- as a handover does; its certificates and its zone follow it. A claim
-- already the tenant's is left untouched and unlocked.
UPDATE domain_claims
SET tenant_id = $2
WHERE hostname = $1
    AND domain_id = $3
    AND tenant_id <> $2
