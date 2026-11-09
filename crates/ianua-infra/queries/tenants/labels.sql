-- The display names of the tenants with the given ids, for the audit trail to name them by.
SELECT id, display_name AS name
FROM tenants
WHERE id = ANY($1)
