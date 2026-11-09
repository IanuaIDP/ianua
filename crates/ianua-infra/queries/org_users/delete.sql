-- Removes an organization member for good; what is kept about them goes
-- with them, by the foreign keys that cascade.
DELETE FROM org_users
WHERE id = $1
