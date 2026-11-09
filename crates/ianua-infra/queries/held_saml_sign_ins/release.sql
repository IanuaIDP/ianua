-- Lets go of the sign-in request a tenant holds under the given id, once
-- it is answered.
DELETE FROM held_saml_sign_ins
WHERE tenant_id = $1 AND id = $2
