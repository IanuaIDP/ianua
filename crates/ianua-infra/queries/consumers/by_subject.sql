-- The consumer of a tenant signing in with tokens of the given issuer and
-- subject: the one using them now, or else the one whose replaced
-- credential they were.
SELECT id, name, description, credential_kind, key_prefix, key_hash, cert_fingerprint,
       jwt_issuer, jwt_subject, jwks_uri, credential_expires_at, previous_kind,
       previous_key_prefix, previous_key_hash, previous_cert_fingerprint, previous_jwt_issuer,
       previous_jwt_subject, previous_jwks_uri, previous_expires_at, previous_until,
       quota_requests, quota_period, status, clearance, created_by, created_at, updated_at
FROM consumers
WHERE tenant_id = $1
  AND (current_credential = 'jwt_bearer' || chr(31) || $2 || chr(31) || $3
       OR previous_credential = 'jwt_bearer' || chr(31) || $2 || chr(31) || $3)
ORDER BY current_credential IS DISTINCT FROM 'jwt_bearer' || chr(31) || $2 || chr(31) || $3, id
LIMIT 1
