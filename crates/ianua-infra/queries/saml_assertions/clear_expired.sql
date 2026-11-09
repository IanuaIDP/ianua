-- Forgets a tenant's spent assertions that expired by the given time: no
-- answer carrying one is taken any more.
DELETE FROM saml_assertions
WHERE tenant_id = $1 AND expires_at <= $2
