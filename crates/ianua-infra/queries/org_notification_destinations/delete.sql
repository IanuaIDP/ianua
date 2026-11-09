-- Deletes one destination of an organization.
DELETE FROM org_notification_destinations
WHERE organization_id = $1 AND id = $2
