-- Remembers that a session of a tenant signed in to one of its SAML apps.
-- The same sign-in kept again is kept once.
INSERT INTO saml_app_sessions (tenant_id, session_id, provider_id, name_id, session_index)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, session_id, provider_id, session_index) DO UPDATE SET
    name_id = EXCLUDED.name_id
