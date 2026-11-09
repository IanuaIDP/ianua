-- How many channels an organization posts notifications to against its
-- plan, paused ones too.
SELECT count(*) AS "count!"
FROM org_notification_destinations
WHERE organization_id = $1
