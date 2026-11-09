-- Lets go of a tenant's held sign-in requests that arrived by the given
-- time, too long ago to be answered.
DELETE FROM held_saml_sign_ins
WHERE tenant_id = $1 AND arrived_at <= $2
