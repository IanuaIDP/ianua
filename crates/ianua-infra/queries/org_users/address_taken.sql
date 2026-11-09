-- Whether any organization has an account at the given address.
SELECT EXISTS (SELECT 1 FROM org_users WHERE email = $1) AS "taken!"
