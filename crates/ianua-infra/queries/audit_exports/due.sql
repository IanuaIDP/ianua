-- The exports of any log due to end, oldest first, at most the given
-- number: pending ones asked for before the write deadline, and ready
-- ones whose download window is over.
SELECT due.id AS "id!", due.log AS "log!", due.organization_id, due.tenant_id,
       due.requested_by AS "requested_by!", due.record_filter AS "record_filter!",
       due.format AS "format!", due.status AS "status!", due.state_at, due.available_until,
       due.row_count, due.requested_at AS "requested_at!", due.file_sha256, due.seal
FROM (
    (SELECT id, log, organization_id, tenant_id, requested_by, record_filter, format, status,
            state_at, available_until, row_count, requested_at, file_sha256, seal
     FROM audit_exports
     WHERE status = 'pending' AND requested_at <= $1
     ORDER BY requested_at, id
     LIMIT $3)
    UNION ALL
    (SELECT id, log, organization_id, tenant_id, requested_by, record_filter, format, status,
            state_at, available_until, row_count, requested_at, file_sha256, seal
     FROM audit_exports
     WHERE status = 'ready' AND available_until <= $2
     ORDER BY available_until, id
     LIMIT $3)
) AS due
ORDER BY due.requested_at, due.id
LIMIT $3
