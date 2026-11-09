-- The break-glass grant of a tenant with the given id.
SELECT id, user_id, grantee_person, system_permissions, custom_permissions, reason,
       approver_kind, approver_id, approver_person, expires_at, revoked_at, created_at
FROM break_glass_grants
WHERE tenant_id = $1 AND id = $2
