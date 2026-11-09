-- The break-glass policy a tenant set, if it set one.
SELECT self_service_system, self_service_custom, updated_at
FROM break_glass_policies
WHERE tenant_id = $1
