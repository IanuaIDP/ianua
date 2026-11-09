-- How many SAML apps a tenant signs people in to against its plan,
-- disabled ones too.
SELECT count(*) AS "count!"
FROM saml_service_providers
WHERE tenant_id = $1
