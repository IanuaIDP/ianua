-- The titles of an organization member's notifications with the given ids, for the audit trail to name them by.
SELECT id, title AS name
FROM org_notifications
WHERE organization_id = $1 AND org_user_id = $2 AND id = ANY($3)
