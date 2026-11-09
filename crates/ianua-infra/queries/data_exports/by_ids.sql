-- Hydrates only the export requests selected by a bounded keyset page.
SELECT id, user_id, scope, asked_by, status, ready_at, available_until, requested_at
FROM data_exports
WHERE tenant_id = $1 AND id = ANY($2)
