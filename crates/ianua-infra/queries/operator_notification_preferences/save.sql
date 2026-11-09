-- Replaces an operator's choices with the categories and channels given,
-- in one statement: the categories left out are dropped, the others kept
-- with their new channel.
WITH dropped AS (
    DELETE FROM operator_notification_preferences
    WHERE operator_id = $1 AND NOT (category = ANY($2::text[]))
)
INSERT INTO operator_notification_preferences (operator_id, category, channel)
SELECT $1, chosen.category, chosen.channel
FROM UNNEST($2::text[], $3::text[]) AS chosen (category, channel)
ON CONFLICT (operator_id, category) DO UPDATE
SET channel = EXCLUDED.channel
