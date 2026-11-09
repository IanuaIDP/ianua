-- Keeps a delegation request: a new one is added, a known one of the same
-- tenant takes its answer. The agent asking, the person asked, what it
-- asks for and when it asked never change. A known one is written over
-- only while it still waits, or with the same answer again, so a copy
-- read before an answer never grants a request already refused or grants
-- one twice.
INSERT INTO delegation_requests
    (id, tenant_id, agent_id, asked_of_kind, asked_of_id, asked_of_person, granted, limits,
     reason, state, delegation_id, decided_at, created_at, expires_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT (id) DO UPDATE SET
    state = EXCLUDED.state,
    delegation_id = EXCLUDED.delegation_id,
    decided_at = EXCLUDED.decided_at,
    expires_at = EXCLUDED.expires_at,
    updated_at = EXCLUDED.updated_at
WHERE delegation_requests.tenant_id = EXCLUDED.tenant_id
  AND (
      delegation_requests.state = 'pending'
      OR (delegation_requests.state = EXCLUDED.state
          AND delegation_requests.delegation_id IS NOT DISTINCT FROM EXCLUDED.delegation_id
          AND delegation_requests.decided_at IS NOT DISTINCT FROM EXCLUDED.decided_at)
  )
