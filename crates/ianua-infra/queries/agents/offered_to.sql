-- The agents of a tenant offered to one account, open or lapsed, oldest
-- first.
SELECT id, name, description, owner_kind, owner_id, owner_person, offered_to_kind,
       offered_to_id, offered_to_person, offered_at, offer_expires_at, status,
       attestation_policy, reattestation_required_since, last_attested_at, created_at,
       updated_at
FROM agents
WHERE tenant_id = $1 AND offered_to_kind = $2 AND offered_to_id = $3
ORDER BY created_at, id
