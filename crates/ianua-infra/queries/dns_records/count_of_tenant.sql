-- How many record sets a tenant holds across every zone it delegated,
-- against its plan. A row is one record set: a name and kind in a zone.
SELECT count(*) AS "count!"
FROM dns_records
WHERE tenant_id = $1
