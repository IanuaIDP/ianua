-- The break-glass grants of a tenant to any of the given users still
-- running at the given time: not revoked, and not yet over.
SELECT id, user_id, grantee_person, system_permissions, custom_permissions, reason,
       approver_kind, approver_id, approver_person, expires_at, revoked_at, created_at
FROM break_glass_grants
WHERE tenant_id = $1 AND user_id = ANY($2) AND expires_at > $3 AND revoked_at IS NULL
ORDER BY created_at, id
