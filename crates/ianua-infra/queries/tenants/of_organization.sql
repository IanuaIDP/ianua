-- The tenants an organization holds, every one not deleted, for the reads
-- that span an organization's tenants.
SELECT ARRAY(
    SELECT t.id FROM tenants t
    WHERE t.organization_id = $1 AND t.status <> 'deleted'
    ORDER BY t.id
) AS "tenants!"
