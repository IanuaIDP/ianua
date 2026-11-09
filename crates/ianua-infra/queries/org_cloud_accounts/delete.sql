-- Removes an organization's connection to one cloud, its credential and
-- external id with it.
DELETE FROM org_cloud_accounts
WHERE organization_id = $1 AND provider = $2
