-- The organization API key, active and not expired, kept as a digest, with
-- its organization, the member who made it and its end.
SELECT id, organization_id, created_by, expires_at
FROM org_api_keys
WHERE key_hash = $1 AND status = 'active' AND (expires_at IS NULL OR expires_at > $2)
