-- Takes one role of a tenant away from everyone given it straight.
DELETE FROM role_assignments
WHERE tenant_id = $1 AND role_id = $2
