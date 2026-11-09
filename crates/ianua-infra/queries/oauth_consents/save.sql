-- Keeps the consent one person of one tenant gave one client: a new one is
-- added, a known one takes its new scopes and the time they were given.
INSERT INTO oauth_consents (tenant_id, user_id, client_id, scopes, granted_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, user_id, client_id) DO UPDATE SET
    scopes = EXCLUDED.scopes,
    granted_at = EXCLUDED.granted_at
