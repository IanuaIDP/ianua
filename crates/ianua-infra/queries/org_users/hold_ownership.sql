-- Serializes changes that can remove an active organization owner. Acquire
-- before reading owners or locking member rows, and retain until the unit of
-- work commits. A separate following read sees the preceding holder's commit.
SELECT pg_advisory_xact_lock(hashtextextended('ianua.org_ownership:' || $1::uuid::text, 0))::text
    AS "held!"
