-- Takes one payment provider event about one organization, answering
-- whether it was taken for the first time, and lets go of that
-- organization's events taken before the given moment. A second delivery
-- of an event still being taken waits for the first to commit.
WITH taken AS (
    INSERT INTO payment_events (event_id, organization_id, created_at, received_at)
    VALUES ($1, $2, $3, $4)
    ON CONFLICT (event_id) DO NOTHING
    RETURNING event_id
), cleared AS (
    DELETE FROM payment_events
    WHERE organization_id = $2 AND received_at < $5
    RETURNING event_id
)
SELECT EXISTS (SELECT 1 FROM taken) AS "first!"
