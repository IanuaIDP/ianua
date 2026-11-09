-- Forgets a tenant's OIDC sign-ins whose time to be answered ran out by
-- the given time.
DELETE FROM oidc_flows
WHERE tenant_id = $1 AND lapses_at <= $2
