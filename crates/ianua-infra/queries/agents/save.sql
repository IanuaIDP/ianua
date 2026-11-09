-- Keeps an agent: a new one is added, a known one of the same tenant takes
-- the new values. Its tenant and its creation time never change, and a
-- revoked one stays revoked, whatever a copy read before the revoke says.
INSERT INTO agents
    (id, tenant_id, name, description, owner_kind, owner_id, owner_person, offered_to_kind,
     offered_to_id, offered_to_person, offered_at, offer_expires_at, status,
     attestation_policy, reattestation_required_since, last_attested_at, created_at,
     updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    owner_kind = EXCLUDED.owner_kind,
    owner_id = EXCLUDED.owner_id,
    owner_person = EXCLUDED.owner_person,
    offered_to_kind = EXCLUDED.offered_to_kind,
    offered_to_id = EXCLUDED.offered_to_id,
    offered_to_person = EXCLUDED.offered_to_person,
    offered_at = EXCLUDED.offered_at,
    offer_expires_at = EXCLUDED.offer_expires_at,
    status = CASE
        WHEN agents.status = 'revoked' THEN 'revoked'
        ELSE EXCLUDED.status
    END,
    attestation_policy = EXCLUDED.attestation_policy,
    reattestation_required_since = EXCLUDED.reattestation_required_since,
    last_attested_at = EXCLUDED.last_attested_at,
    updated_at = EXCLUDED.updated_at
WHERE agents.tenant_id = EXCLUDED.tenant_id
