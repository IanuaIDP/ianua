-- Links from the second wave's tables to tenant sessions, made once both
-- exist.

-- A code is consented in one session and is of no use without it.
ALTER TABLE oauth_codes
    ADD CONSTRAINT oauth_codes_session_fkey FOREIGN KEY (tenant_id, session_id)
        REFERENCES sessions (tenant_id, id) ON DELETE CASCADE;
CREATE INDEX oauth_codes_of_session ON oauth_codes (tenant_id, session_id);

-- A refresh grant outlives a purged session: it only forgets which one it
-- was given in, as a grant given on a second screen never knew.
ALTER TABLE oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_session_fkey FOREIGN KEY (tenant_id, session_id)
        REFERENCES sessions (tenant_id, id) ON DELETE SET NULL (session_id);

-- The provider's session is followed only while ours stands.
ALTER TABLE provider_sessions
    ADD CONSTRAINT provider_sessions_session_fkey FOREIGN KEY (tenant_id, session_id)
        REFERENCES sessions (tenant_id, id) ON DELETE CASCADE;

-- An app's sign-in stands on our session and goes with it.
ALTER TABLE saml_app_sessions
    ADD CONSTRAINT saml_app_sessions_session_fkey FOREIGN KEY (tenant_id, session_id)
        REFERENCES sessions (tenant_id, id) ON DELETE CASCADE;
