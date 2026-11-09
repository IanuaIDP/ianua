-- Notes when the verification sweep last asked DNS about one registered
-- domain of one tenant.
UPDATE registered_domains SET last_checked_at = $3
WHERE tenant_id = $1 AND id = $2
