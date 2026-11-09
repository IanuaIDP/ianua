-- Holds a sign-in request that just reached a tenant, as it arrived.
INSERT INTO held_saml_sign_ins
    (id, tenant_id, binding, signature_algorithm, signature, signed_query, message,
     relay_state, arrived_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
