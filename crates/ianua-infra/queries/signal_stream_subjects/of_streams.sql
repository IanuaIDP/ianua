-- The subjects the signal streams of a tenant with the given ids list,
-- each stream's in the order it listed them.
SELECT stream_id, user_id, agent_id
FROM signal_stream_subjects
WHERE tenant_id = $1 AND stream_id = ANY($2)
ORDER BY stream_id, position
