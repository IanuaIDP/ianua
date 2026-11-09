-- Gives a stored agent of the tenant its new values, only while it is still
-- at the version the caller read, and answers the version it is stored at
-- now. Every write moves the version on, so a second write from the same
-- read finds no row; none comes back either when the agent is gone. Its
-- tenant and creation time never change, and a revoked one stays revoked.
UPDATE agents SET
    name = $4,
    description = $5,
    owner_kind = $6,
    owner_id = $7,
    owner_person = $8,
    offered_to_kind = $9,
    offered_to_id = $10,
    offered_to_person = $11,
    offered_at = $12,
    offer_expires_at = $13,
    status = CASE WHEN status = 'revoked' THEN 'revoked' ELSE $14::text END,
    attestation_policy = $15,
    reattestation_required_since = $16,
    last_attested_at = $17,
    updated_at = GREATEST($18, updated_at + interval '1 microsecond')
WHERE tenant_id = $1 AND id = $2 AND updated_at = $3
RETURNING updated_at
