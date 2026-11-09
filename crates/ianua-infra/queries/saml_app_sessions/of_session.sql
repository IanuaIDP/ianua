-- The SAML apps a session of a tenant signed in to, each sign-in once.
SELECT session_id, provider_id, name_id, session_index
FROM saml_app_sessions
WHERE tenant_id = $1 AND session_id = $2
ORDER BY provider_id, session_index
