-- Deletes every certificate of one domain but the newest saved: each one a
-- newer certificate of the same tenant and domain stands behind.
DELETE FROM domain_certificates old
USING domain_certificates newer
WHERE old.domain_id = $1
  AND newer.tenant_id = old.tenant_id
  AND newer.domain_id = old.domain_id
  AND newer.saved_order > old.saved_order
