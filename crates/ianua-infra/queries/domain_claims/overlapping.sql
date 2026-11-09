-- Every claim on a name that overlaps one, whichever tenant holds it: the
-- name itself and the names above it, by their keys, and the names below
-- it, whose keys run between the two bounds.
SELECT hostname, tenant_id, domain_id
FROM domain_claims
WHERE overlap_key = ANY($1) OR (overlap_key > $2 AND overlap_key < $3)
