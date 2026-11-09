-- One destination of an organization, by its id.
SELECT id, organization_id, name, kind, hook, url, signing_secret, categories, minimum_severity,
       state, created_at, updated_at
FROM org_notification_destinations
WHERE organization_id = $1 AND id = $2
