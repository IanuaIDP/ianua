-- Publishes a challenge, replacing any earlier one for the same token.
INSERT INTO acme_challenges (token, key_authorization, domain, expires_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (token) DO UPDATE SET
    key_authorization = EXCLUDED.key_authorization,
    domain = EXCLUDED.domain,
    expires_at = EXCLUDED.expires_at
