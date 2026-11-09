-- How many exports of the given log the worker is still writing.
SELECT count(*) AS "count!"
FROM audit_exports
WHERE log = $1 AND status = 'pending'
    AND organization_id IS NOT DISTINCT FROM $2 AND tenant_id IS NOT DISTINCT FROM $3
