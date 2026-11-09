-- The sign-in request a tenant holds under the given id, if it arrived
-- after the given time and so may still be answered.
SELECT id, binding, signature_algorithm, signature, signed_query, message, relay_state,
       arrived_at
FROM held_saml_sign_ins
WHERE tenant_id = $1 AND id = $2 AND arrived_at > $3
