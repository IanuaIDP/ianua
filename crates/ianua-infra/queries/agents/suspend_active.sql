-- Suspends every active agent of a tenant at the given time, always moving
-- each one's last change on, so a copy read before the stop can never be
-- saved over it. Agents already suspended or revoked are left alone.
UPDATE agents
SET status = 'suspended', updated_at = GREATEST($2, updated_at + interval '1 microsecond')
WHERE tenant_id = $1 AND status = 'active'
