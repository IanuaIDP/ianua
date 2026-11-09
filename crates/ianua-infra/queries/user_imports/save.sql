-- Keeps an import: a new one is added, a known one of the same tenant takes
-- its progress. Who started it, how many records it holds and when it was
-- kept never change. Answers whether the row is new, so its records are
-- written once, with it.
INSERT INTO user_imports
    (id, tenant_id, started_by, status, ended_at, total, done, imported,
     refused_lines, refused_reasons, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status,
    ended_at = EXCLUDED.ended_at,
    done = EXCLUDED.done,
    imported = EXCLUDED.imported,
    refused_lines = EXCLUDED.refused_lines,
    refused_reasons = EXCLUDED.refused_reasons
WHERE user_imports.tenant_id = EXCLUDED.tenant_id
RETURNING (xmax = 0) AS "inserted!"
