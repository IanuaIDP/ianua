-- The name and address of each organization member with the given ids, as
-- an audit log shows who acted.
SELECT id, display_name, email
FROM org_users
WHERE id = ANY($1)
