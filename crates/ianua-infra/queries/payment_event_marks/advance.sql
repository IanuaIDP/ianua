-- Moves the newest event of one kind applied to one organization on to the
-- given creation time, unless an event created later was applied, and
-- answers whether it moved. Two events of one kind at once are weighed one
-- after the other.
WITH moved AS (
    INSERT INTO payment_event_marks (organization_id, stream, newest_at)
    VALUES ($1, $2, $3)
    ON CONFLICT (organization_id, stream) DO UPDATE SET newest_at = EXCLUDED.newest_at
    WHERE payment_event_marks.newest_at <= EXCLUDED.newest_at
    RETURNING organization_id
)
SELECT EXISTS (SELECT 1 FROM moved) AS "newest!"
