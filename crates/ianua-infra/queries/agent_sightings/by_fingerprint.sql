-- The sighting a tenant keeps for one caller, as one source saw it.
SELECT id, source, fingerprint, calls_itself, seen_count, first_seen_at, last_seen_at, state,
       registered_agent_id, decided_at, updated_at
FROM agent_sightings
WHERE tenant_id = $1 AND source = $2 AND fingerprint = $3
