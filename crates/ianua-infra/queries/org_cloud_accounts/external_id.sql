-- The sealed external id an organization's connection to one cloud was
-- begun with.
SELECT external_id_sealed
FROM org_cloud_accounts
WHERE organization_id = $1 AND provider = $2
