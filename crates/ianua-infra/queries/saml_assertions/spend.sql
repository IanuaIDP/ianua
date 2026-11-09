-- Records a SAML assertion of a tenant as spent until it expires,
-- answering its id only when this statement was the one that spent it.
INSERT INTO saml_assertions (tenant_id, assertion_id, expires_at)
VALUES ($1, $2, $3)
ON CONFLICT (tenant_id, assertion_id) DO NOTHING
RETURNING assertion_id
