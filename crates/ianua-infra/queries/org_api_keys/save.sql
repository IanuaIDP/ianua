-- Keeps an organization API key: a new one is added, a known one takes the
-- new values. Its organization, secret, creator, parent and creation time
-- never change.
INSERT INTO org_api_keys
    (id, organization_id, name, key_prefix, key_hash, scopes, created_by, parent_key_id,
     expires_at, last_used_at, status, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    scopes = EXCLUDED.scopes,
    expires_at = EXCLUDED.expires_at,
    last_used_at = EXCLUDED.last_used_at,
    status = EXCLUDED.status
