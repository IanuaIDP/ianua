-- Keeps an export request: a new one is added, a known one of the same
-- tenant takes where it stands. Whose it is, what it holds, who asked and
-- when never change.
INSERT INTO data_exports
    (id, tenant_id, user_id, scope, asked_by, status, ready_at, available_until,
     requested_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status,
    ready_at = EXCLUDED.ready_at,
    available_until = EXCLUDED.available_until
WHERE data_exports.tenant_id = EXCLUDED.tenant_id
