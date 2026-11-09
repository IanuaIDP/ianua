-- Every break-glass grant of a tenant, oldest first.
SELECT id, user_id, grantee_person, system_permissions, custom_permissions, reason,
       approver_kind, approver_id, approver_person, expires_at, revoked_at, created_at
FROM break_glass_grants
WHERE tenant_id = $1
ORDER BY created_at, id
