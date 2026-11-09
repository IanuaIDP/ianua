-- Keeps a sighting: a new one is added, a known one of the same tenant
-- takes the new values. A new one whose source and fingerprint another
-- sighting holds is refused by agent_sightings_fingerprint_key. Where it
-- was seen, what tells it apart and when it was first seen never change.
INSERT INTO agent_sightings
    (id, tenant_id, source, fingerprint, calls_itself, seen_count, first_seen_at, last_seen_at,
     state, registered_agent_id, decided_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (id) DO UPDATE SET
    calls_itself = EXCLUDED.calls_itself,
    seen_count = EXCLUDED.seen_count,
    last_seen_at = EXCLUDED.last_seen_at,
    state = EXCLUDED.state,
    registered_agent_id = EXCLUDED.registered_agent_id,
    decided_at = EXCLUDED.decided_at,
    updated_at = EXCLUDED.updated_at
WHERE agent_sightings.tenant_id = EXCLUDED.tenant_id
