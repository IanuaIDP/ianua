-- Clears away a role of a tenant given straight to one principal, only
-- while its end has still come by the given time. One given again since,
-- in force once more, is left.
DELETE FROM role_assignments
WHERE tenant_id = $1 AND role_id = $2 AND principal_kind = $3 AND principal_id = $4
  AND expires_at IS NOT NULL AND expires_at <= $5
