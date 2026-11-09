-- The names and addresses of an organization's members with the given ids, for the audit trail to name them by.
SELECT id, display_name, email
FROM org_users
WHERE organization_id = $1 AND id = ANY($2)
