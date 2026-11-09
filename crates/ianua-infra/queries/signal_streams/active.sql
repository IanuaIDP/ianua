-- Every active signal stream of a tenant, oldest first, without the
-- subjects they list: a signal fans out to all of them in one pass.
SELECT id, endpoint, endpoint_challenge, delivery_method, authorization_sealed,
       receiver_key_hash, signal_types, default_subjects, status, consecutive_failures,
       created_at, updated_at
FROM signal_streams
WHERE tenant_id = $1 AND status = 'active'
ORDER BY created_at, id
