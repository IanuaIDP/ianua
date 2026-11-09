-- The consumers of a tenant with the given ids.
SELECT id, name, description, credential_kind, key_prefix, key_hash, cert_fingerprint,
       jwt_issuer, jwt_subject, jwks_uri, credential_expires_at, previous_kind,
       previous_key_prefix, previous_key_hash, previous_cert_fingerprint, previous_jwt_issuer,
       previous_jwt_subject, previous_jwks_uri, previous_expires_at, previous_until,
       quota_requests, quota_period, status, clearance, created_by, created_at, updated_at
FROM consumers
WHERE tenant_id = $1 AND id = ANY($2)
