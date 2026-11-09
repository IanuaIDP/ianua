-- Lease one due pair whose tenant still serves the address.
WITH candidate AS (
    SELECT p.root FROM platform_certificates p JOIN tenants t ON t.id = p.tenant_id
    WHERE p.next_attempt <= now() AND (p.lease_until IS NULL OR p.lease_until <= now())
        AND (p.expires_at IS NULL OR p.expires_at <= now() + interval '30 days')
        AND t.status IN ('active', 'provisioning') AND (NOT p.readable OR t.readable_address)
    ORDER BY p.next_attempt, p.root LIMIT 1 FOR UPDATE OF p SKIP LOCKED
)
UPDATE platform_certificates p SET attempt_id = $1, lease_until = now() + interval '10 minutes'
FROM candidate WHERE p.root = candidate.root
RETURNING p.root, p.tenant_id, p.readable
