-- Forgets every SAML app a session of a tenant signed in to.
DELETE FROM saml_app_sessions
WHERE tenant_id = $1 AND session_id = $2
