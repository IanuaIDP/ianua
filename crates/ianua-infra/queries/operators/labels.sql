-- The sign-in addresses of the operators with the given ids, for the audit trail to name them by.
SELECT id, email AS name
FROM operators
WHERE id = ANY($1)
