-- Records a SAML assertion as spent until it expires, answering its id only
-- when this statement was the one that spent it.
INSERT INTO org_saml_assertions (assertion_id, expires_at)
VALUES ($1, $2)
ON CONFLICT (assertion_id) DO NOTHING
RETURNING assertion_id
