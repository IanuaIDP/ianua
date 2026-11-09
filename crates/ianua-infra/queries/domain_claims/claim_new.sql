-- Claims a hostname for a new registration of one tenant, only while no
-- other registration holds the name itself and no other tenant's claim
-- that still holds its name sits at it, above it or below it: the keys at
-- and above, and the keys between the two bounds below. A claim still
-- holds its name while it is proved, never proved and made after the first
-- cutoff, or its proof lost after the second. Nothing is written when one
-- stands in the way.
INSERT INTO domain_claims
    (hostname, overlap_key, tenant_id, domain_id, verified, claimed_at, failed_at)
SELECT $1::text, $2::text, $3::uuid, $4::uuid, $5::boolean, $6::timestamptz, $7::timestamptz
WHERE NOT EXISTS (
    SELECT 1
    FROM domain_claims held
    WHERE held.tenant_id <> $3::uuid
      AND (held.overlap_key = ANY($8::text[])
        OR (held.overlap_key > $9::text AND held.overlap_key < $10::text))
      AND (held.verified
        OR (held.failed_at IS NULL AND held.claimed_at > $11::timestamptz)
        OR held.failed_at > $12::timestamptz)
)
ON CONFLICT (hostname) DO NOTHING
