-- Keeps a break-glass grant: a new one is added, a known one of the same
-- tenant and user takes its revocation. What it grants, to whom, why, who
-- approved it and when it ends never change. A revoked grant takes nothing
-- new, so a save of a copy read before the revocation never makes it live
-- again or moves the time it was revoked.
INSERT INTO break_glass_grants
    (id, tenant_id, user_id, grantee_person, system_permissions, custom_permissions, reason,
     approver_kind, approver_id, approver_person, expires_at, revoked_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (id) DO UPDATE SET
    revoked_at = EXCLUDED.revoked_at
WHERE break_glass_grants.tenant_id = EXCLUDED.tenant_id
    AND break_glass_grants.user_id = EXCLUDED.user_id
    AND break_glass_grants.revoked_at IS NULL
