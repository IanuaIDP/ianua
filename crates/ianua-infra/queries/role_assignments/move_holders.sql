-- Gives everyone still holding one role of a tenant at the given time
-- another one instead, from the given actor at that time, ending when
-- their hold on the first one ends. A hold that already ran out moves
-- nothing, and someone who already holds the other role keeps what they
-- hold.
INSERT INTO role_assignments
    (tenant_id, role_id, principal_kind, principal_id, assigned_by, assigned_at, expires_at)
SELECT held.tenant_id, $3, held.principal_kind, held.principal_id, $4, $5, held.expires_at
FROM role_assignments held
WHERE held.tenant_id = $1 AND held.role_id = $2
  AND (held.expires_at IS NULL OR held.expires_at > $5)
ON CONFLICT (tenant_id, role_id, principal_kind, principal_id) DO NOTHING
