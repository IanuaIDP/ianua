-- Deletes one certificate of one tenant, with its sealed key.
DELETE FROM domain_certificates
WHERE tenant_id = $1 AND id = $2
