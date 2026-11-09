-- The agents of a tenant with the given ids.
SELECT id, name, description, owner_kind, owner_id, owner_person, offered_to_kind,
       offered_to_id, offered_to_person, offered_at, offer_expires_at, status,
       attestation_policy, reattestation_required_since, last_attested_at, created_at,
       updated_at
FROM agents
WHERE tenant_id = $1 AND id = ANY($2)
