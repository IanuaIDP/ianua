-- Keeps a signal stream without its subjects: a new one is added, a known
-- one of the same tenant takes the new values. Its tenant and its creation
-- time never change.
--
-- The endpoint's challenge is none once the endpoint is verified; while it
-- waits, it is the one just issued, or else the one already kept for the
-- same endpoint. A stream waiting on its endpoint with neither is not
-- written at all, so a row never waits on a challenge nobody sent.
WITH kept AS (
    SELECT endpoint_challenge
    FROM signal_streams
    WHERE tenant_id = $2 AND id = $1 AND endpoint = $3
),
challenge AS (
    SELECT CASE WHEN $4::text = 'verified' THEN NULL
                ELSE coalesce($5::text, (SELECT kept.endpoint_challenge FROM kept))
           END AS value
)
INSERT INTO signal_streams
    (id, tenant_id, endpoint, endpoint_challenge, delivery_method, authorization_sealed,
     receiver_key_hash, signal_types, default_subjects, status, consecutive_failures,
     created_at, updated_at)
SELECT $1::uuid, $2::uuid, $3::text, challenge.value, $6::text, $7::text, $8::text,
       $9::text[], $10::text, $11::text, $12::bigint, $13::timestamptz, $14::timestamptz
FROM challenge
WHERE $4::text = 'verified' OR challenge.value IS NOT NULL
ON CONFLICT (id) DO UPDATE SET
    endpoint = EXCLUDED.endpoint,
    endpoint_challenge = EXCLUDED.endpoint_challenge,
    delivery_method = EXCLUDED.delivery_method,
    authorization_sealed = EXCLUDED.authorization_sealed,
    receiver_key_hash = EXCLUDED.receiver_key_hash,
    signal_types = EXCLUDED.signal_types,
    default_subjects = EXCLUDED.default_subjects,
    status = EXCLUDED.status,
    consecutive_failures = EXCLUDED.consecutive_failures,
    updated_at = EXCLUDED.updated_at
WHERE signal_streams.tenant_id = EXCLUDED.tenant_id
