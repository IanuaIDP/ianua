-- Keeps a consumer: a new one is added, a known one of the same tenant
-- takes the new values. Its tenant, its maker and its creation time never
-- change.
INSERT INTO consumers
    (id, tenant_id, name, description, credential_kind, key_prefix, key_hash,
     cert_fingerprint, jwt_issuer, jwt_subject, jwks_uri, credential_expires_at,
     previous_kind, previous_key_prefix, previous_key_hash, previous_cert_fingerprint,
     previous_jwt_issuer, previous_jwt_subject, previous_jwks_uri, previous_expires_at,
     previous_until, quota_requests, quota_period, status, clearance, created_by,
     created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
        $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    credential_kind = EXCLUDED.credential_kind,
    key_prefix = EXCLUDED.key_prefix,
    key_hash = EXCLUDED.key_hash,
    cert_fingerprint = EXCLUDED.cert_fingerprint,
    jwt_issuer = EXCLUDED.jwt_issuer,
    jwt_subject = EXCLUDED.jwt_subject,
    jwks_uri = EXCLUDED.jwks_uri,
    credential_expires_at = EXCLUDED.credential_expires_at,
    previous_kind = EXCLUDED.previous_kind,
    previous_key_prefix = EXCLUDED.previous_key_prefix,
    previous_key_hash = EXCLUDED.previous_key_hash,
    previous_cert_fingerprint = EXCLUDED.previous_cert_fingerprint,
    previous_jwt_issuer = EXCLUDED.previous_jwt_issuer,
    previous_jwt_subject = EXCLUDED.previous_jwt_subject,
    previous_jwks_uri = EXCLUDED.previous_jwks_uri,
    previous_expires_at = EXCLUDED.previous_expires_at,
    previous_until = EXCLUDED.previous_until,
    quota_requests = EXCLUDED.quota_requests,
    quota_period = EXCLUDED.quota_period,
    status = EXCLUDED.status,
    clearance = EXCLUDED.clearance,
    updated_at = EXCLUDED.updated_at
WHERE consumers.tenant_id = EXCLUDED.tenant_id
