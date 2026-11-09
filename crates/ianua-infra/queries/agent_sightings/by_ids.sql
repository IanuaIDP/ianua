-- The agent sightings of a tenant with the given ids.
SELECT id, source, fingerprint, calls_itself, seen_count, first_seen_at, last_seen_at, state,
       registered_agent_id, decided_at, updated_at
FROM agent_sightings
WHERE tenant_id = $1 AND id = ANY($2)
