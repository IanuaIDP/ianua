-- Takes a role of a tenant given straight to one principal away.
DELETE FROM role_assignments
WHERE tenant_id = $1 AND role_id = $2 AND principal_kind = $3 AND principal_id = $4
