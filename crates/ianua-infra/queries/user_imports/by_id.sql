-- The import of a tenant with the given id, without its records, with how
-- many it was sent.
SELECT id, started_by, status, ended_at, total, done, imported, refused_lines,
       refused_reasons, created_at
FROM user_imports
WHERE tenant_id = $1 AND id = $2
