-- Every key of an organization minted through the given key, directly or
-- through a key minted through it, at any depth, oldest first. The walk
-- keeps to the organization, and a key reached twice is walked once.
WITH RECURSIVE minted (id) AS (
    SELECT child.id
    FROM org_api_keys child
    WHERE child.organization_id = $1 AND child.parent_key_id = $2
    UNION
    SELECT child.id
    FROM org_api_keys child
    JOIN minted ON child.parent_key_id = minted.id
    WHERE child.organization_id = $1
)
SELECT id, organization_id, name, key_prefix, key_hash, scopes, created_by, parent_key_id,
       expires_at, last_used_at, status, created_at
FROM org_api_keys
WHERE id IN (SELECT minted.id FROM minted)
ORDER BY created_at, id
