-- The sandboxes of one tenant that the ids name.
SELECT id, name, kind, language, status, latest_version, created_by, created_at, updated_at
FROM sandboxes
WHERE tenant_id = $1 AND id = ANY($2)
