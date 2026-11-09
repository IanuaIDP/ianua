-- The LDAP client certificates of a tenant with the given ids.
SELECT id, user_id, fingerprint, device_label, issued_at, expires_at, revoked_at
FROM ldap_certificates
WHERE tenant_id = $1 AND id = ANY($2)
