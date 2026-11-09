-- How many notifications of a member's inbox are not yet read.
SELECT count(*) AS "count!"
FROM org_notifications
WHERE organization_id = $1 AND org_user_id = $2 AND NOT read
