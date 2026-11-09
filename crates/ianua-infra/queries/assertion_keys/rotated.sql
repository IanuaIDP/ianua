-- Every tenant in this database holding an assertion key rotated out and
-- not yet retired, for the sweep that retires it once its overlap is over.
SELECT DISTINCT tenant_id AS "tenant_id!"
FROM assertion_keys
WHERE status = 'rotated'
