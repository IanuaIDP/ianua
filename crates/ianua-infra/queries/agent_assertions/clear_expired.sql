-- Forgets the agent assertions one tenant spent that expired by the given
-- time: none of them is taken any more.
DELETE FROM agent_assertions
WHERE tenant_id = $1 AND expires_at <= $2
