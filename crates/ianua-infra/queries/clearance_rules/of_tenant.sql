-- The clearance rules of a tenant, if it ever wrote any.
SELECT permissions, levels, updated_at
FROM clearance_rules
WHERE tenant_id = $1
