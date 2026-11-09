-- Claims a hostname for one registration of one tenant, with whether the
-- registration proved it and when its proof was lost. A name another
-- registration holds is left as it is, and nothing is written; the
-- registration's own claim moves to the tenant saving it, as a handover
-- does, and keeps up with its proof.
INSERT INTO domain_claims
    (hostname, overlap_key, tenant_id, domain_id, verified, claimed_at, failed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (hostname) DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    verified = EXCLUDED.verified,
    failed_at = EXCLUDED.failed_at
WHERE domain_claims.domain_id = EXCLUDED.domain_id
