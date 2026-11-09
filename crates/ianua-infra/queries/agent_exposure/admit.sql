-- Admits a request of one agent of a tenant to data of the given rank if
-- the agent's mark does not exceed it, raising the mark to that rank in
-- the same statement, and reads the mark back when it was admitted. An
-- agent with no mark has touched nothing, so it is admitted.
INSERT INTO agent_exposure (tenant_id, agent_id, level)
VALUES ($1, $2, $3)
ON CONFLICT (tenant_id, agent_id) DO UPDATE SET level = EXCLUDED.level
WHERE agent_exposure.level <= EXCLUDED.level
RETURNING level
