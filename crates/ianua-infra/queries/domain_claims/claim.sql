-- Claims a hostname for one registration of one tenant, with whether the
-- registration proved it and when its proof was lost. A name another
-- registration holds is left as it is, and nothing is written; the
-- registration's own claim keeps up with its proof. The tenant is never
-- set here: a claim that changes hands moves first through `move.sql`, so
-- this update locks no key a certificate or a zone holds the claim by, and
-- two changes each saving a certificate and then its domain never wait on
-- each other's hold.
INSERT INTO domain_claims
    (hostname, overlap_key, tenant_id, domain_id, verified, claimed_at, failed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (hostname) DO UPDATE SET
    verified = EXCLUDED.verified,
    failed_at = EXCLUDED.failed_at
WHERE domain_claims.domain_id = EXCLUDED.domain_id
    AND domain_claims.tenant_id = EXCLUDED.tenant_id
