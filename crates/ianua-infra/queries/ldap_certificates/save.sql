-- Keeps an LDAP client certificate: a new one is added, a known one of the
-- same tenant takes its revocation. Its holder, fingerprint, label and
-- validity never change.
INSERT INTO ldap_certificates
    (id, tenant_id, user_id, fingerprint, device_label, issued_at, expires_at, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
    revoked_at = EXCLUDED.revoked_at
WHERE ldap_certificates.tenant_id = EXCLUDED.tenant_id
