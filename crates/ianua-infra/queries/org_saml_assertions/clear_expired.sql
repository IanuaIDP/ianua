-- Forgets the spent assertions that expired by the given time: no provider
-- answer carrying one is taken any more.
DELETE FROM org_saml_assertions
WHERE expires_at <= $1
