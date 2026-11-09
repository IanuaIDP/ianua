-- Keeps an audit log export: a new one is added, a known one takes where
-- it stands, with its file's digest and seal. Its log, its asker, what it
-- holds, its format and when it was asked for never change.
INSERT INTO audit_exports
    (id, log, organization_id, tenant_id, requested_by, record_filter, format, status,
     state_at, available_until, row_count, requested_at, file_sha256, seal)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status,
    state_at = EXCLUDED.state_at,
    available_until = EXCLUDED.available_until,
    row_count = EXCLUDED.row_count,
    file_sha256 = EXCLUDED.file_sha256,
    seal = EXCLUDED.seal
