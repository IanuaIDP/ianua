-- The organization API keys with the given ids.
SELECT id, organization_id, name, key_prefix, key_hash, scopes, created_by, parent_key_id,
       expires_at, last_used_at, status, created_at
FROM org_api_keys
WHERE id = ANY($1)
