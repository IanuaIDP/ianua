-- Gives a principal a role of a tenant. One they hold still in force when
-- this one is given is left as it is; one whose end had come by then, not
-- yet cleared by the sweep, is replaced by this one.
INSERT INTO role_assignments
    (tenant_id, role_id, principal_kind, principal_id, assigned_by, assigned_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_id, role_id, principal_kind, principal_id) DO UPDATE SET
    assigned_by = EXCLUDED.assigned_by,
    assigned_at = EXCLUDED.assigned_at,
    expires_at = EXCLUDED.expires_at
WHERE role_assignments.expires_at IS NOT NULL
  AND role_assignments.expires_at <= EXCLUDED.assigned_at
