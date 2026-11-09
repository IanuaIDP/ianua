-- Lowers the mark of one agent of a tenant to the given rank, only while
-- it still holds the rank the person saw and the agent is still stopped.
UPDATE agent_exposure e
SET level = $4
FROM agents a
WHERE e.tenant_id = $1 AND e.agent_id = $2 AND e.level = $3
  AND a.tenant_id = e.tenant_id AND a.id = e.agent_id AND a.status <> 'active'
