-- The export with the given id of the given log, found only under the log
-- it exports.
SELECT id, log, organization_id, tenant_id, requested_by, record_filter, format, status,
       state_at, available_until, row_count, requested_at, file_sha256, seal
FROM audit_exports
WHERE id = $1 AND log = $2
    AND organization_id IS NOT DISTINCT FROM $3 AND tenant_id IS NOT DISTINCT FROM $4
