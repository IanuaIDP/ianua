-- The address of each operator with the given ids, as an audit log shows
-- who acted.
SELECT id, email
FROM operators
WHERE id = ANY($1)
