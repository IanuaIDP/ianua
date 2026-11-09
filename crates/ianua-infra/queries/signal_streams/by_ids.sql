-- The signal streams of a tenant with the given ids, without the subjects
-- they list.
SELECT id, endpoint, endpoint_challenge, delivery_method, authorization_sealed,
       receiver_key_hash, signal_types, default_subjects, status, consecutive_failures,
       created_at, updated_at
FROM signal_streams
WHERE tenant_id = $1 AND id = ANY($2)
