-- The slug and name of each tenant with the given ids, as an audit log
-- shows them beside the tenant's records.
SELECT id, slug, display_name
FROM tenants
WHERE id = ANY($1)
