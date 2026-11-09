-- Writes when, from where and from which countries one tenant's API key
-- was last used, only while it is still kept and still remembers $6, the
-- countries this use read, leaving every other column as stored. Says
-- whether the write landed and whether the key is still kept: a use
-- racing another that noted a new country first writes nothing, so the
-- country is noted once.
WITH written AS (
    UPDATE api_keys
    SET last_used_at = $3, last_used_ip = $4, seen_countries = $5
    WHERE tenant_id = $1 AND id = $2 AND seen_countries = $6
    RETURNING id
)
SELECT
    EXISTS (SELECT 1 FROM written) AS "written!",
    EXISTS (SELECT 1 FROM api_keys WHERE tenant_id = $1 AND id = $2) AS "kept!"
