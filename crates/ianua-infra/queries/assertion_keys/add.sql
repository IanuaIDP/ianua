-- Adds a tenant's new assertion keys, each with its private half sealed.
-- A key saved already is left as it is, so saving a set twice adds once.
INSERT INTO assertion_keys
    (tenant_id, kid, algorithm, public_key, private_key_sealed, status, rotated_at, created_at)
SELECT $1, added.kid, added.algorithm, added.public_key, added.private_key_sealed, added.status,
       added.rotated_at, added.created_at
FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::timestamptz[],
            $8::timestamptz[])
    AS added (kid, algorithm, public_key, private_key_sealed, status, rotated_at, created_at)
ON CONFLICT (tenant_id, kid) DO NOTHING
