-- A person's LDAP client certificates in a tenant, in the order they were
-- issued.
SELECT id, user_id, fingerprint, device_label, issued_at, expires_at, revoked_at
FROM ldap_certificates
WHERE tenant_id = $1 AND user_id = $2
ORDER BY issued_at, id
