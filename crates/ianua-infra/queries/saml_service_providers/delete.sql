-- Removes a SAML app of a tenant, and with it the record of the sessions
-- signed in to it.
DELETE FROM saml_service_providers
WHERE tenant_id = $1 AND id = $2
