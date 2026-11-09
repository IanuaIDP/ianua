-- The timezone of each tenant named, which their workflows' schedules are
-- read in.
SELECT id, timezone
FROM tenants
WHERE id = ANY($1)
