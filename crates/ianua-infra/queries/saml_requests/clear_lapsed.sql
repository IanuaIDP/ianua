-- Forgets a tenant's SAML sign-in requests whose time to be answered ran
-- out by the given time.
DELETE FROM saml_requests
WHERE tenant_id = $1 AND lapses_at <= $2
