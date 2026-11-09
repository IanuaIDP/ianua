-- Which of the given runs a worker still holds a lease on at the moment
-- given.
SELECT leased_id
FROM platform_leases
WHERE leased = 'agent_run' AND leased_id = ANY($1) AND leased_until > $2
