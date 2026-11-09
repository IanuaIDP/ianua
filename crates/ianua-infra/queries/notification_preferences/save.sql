-- Replaces a tenant user's choices with the categories and channels given,
-- in one statement: the categories left out are dropped, the others kept
-- with their new channel.
WITH dropped AS (
    DELETE FROM notification_preferences
    WHERE tenant_id = $1 AND user_id = $2 AND NOT (category = ANY($3::text[]))
)
INSERT INTO notification_preferences (tenant_id, user_id, category, channel)
SELECT $1, $2, chosen.category, chosen.channel
FROM UNNEST($3::text[], $4::text[]) AS chosen (category, channel)
ON CONFLICT (tenant_id, user_id, category) DO UPDATE
SET channel = EXCLUDED.channel
