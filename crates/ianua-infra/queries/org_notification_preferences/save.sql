-- Replaces a member's choices with the categories and channels given, in
-- one statement: the categories left out are dropped, the others kept with
-- their new channel.
WITH dropped AS (
    DELETE FROM org_notification_preferences
    WHERE organization_id = $1 AND org_user_id = $2 AND NOT (category = ANY($3::text[]))
)
INSERT INTO org_notification_preferences (organization_id, org_user_id, category, channel)
SELECT $1, $2, chosen.category, chosen.channel
FROM UNNEST($3::text[], $4::text[]) AS chosen (category, channel)
ON CONFLICT (organization_id, org_user_id, category) DO UPDATE
SET channel = EXCLUDED.channel
