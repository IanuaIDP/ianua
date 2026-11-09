-- Whether a clone is filling the tenant now.
SELECT EXISTS (
    SELECT 1 FROM tenant_clones WHERE tenant_id = $1 AND state = 'copying'
) AS "copying!"
