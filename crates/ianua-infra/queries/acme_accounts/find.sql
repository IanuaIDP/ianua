-- The sealed credentials of the account held with one authority, if any.
SELECT credentials_sealed
FROM acme_accounts
WHERE directory_url = $1
