-- Keeps every key of a tenant's key set in one statement: a new key is
-- added, a known one takes its new standing and expiry. A key's algorithm,
-- its two halves and its creation time never change.
INSERT INTO signing_keys
    (tenant_id, kid, algorithm, public_key, private_key_sealed, status, rotated_at,
     expires_at, created_at)
SELECT $1, kept.kid, kept.algorithm, kept.public_key, kept.private_key_sealed, kept.status,
       kept.rotated_at, kept.expires_at, kept.created_at
FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::timestamptz[],
            $8::timestamptz[], $9::timestamptz[])
    AS kept (kid, algorithm, public_key, private_key_sealed, status, rotated_at, expires_at,
             created_at)
ON CONFLICT (tenant_id, kid) DO UPDATE SET
    status = EXCLUDED.status,
    rotated_at = EXCLUDED.rotated_at,
    expires_at = EXCLUDED.expires_at
