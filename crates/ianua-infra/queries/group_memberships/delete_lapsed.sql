-- Clears away one principal's place in a group of a tenant, only while its
-- end has still come by the given time. A place given again since, in
-- force once more, is left.
DELETE FROM group_memberships
WHERE tenant_id = $1 AND group_id = $2 AND principal_kind = $3 AND principal_id = $4
  AND expires_at IS NOT NULL AND expires_at <= $5
