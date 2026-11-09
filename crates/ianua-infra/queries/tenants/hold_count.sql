-- Holds what one tenant holds against its plan for the running
-- transaction, waiting while another transaction holds it, so a count and
-- the creation it allows are never raced by another creation counted at
-- the same moment. Inside a unit of work it holds until the unit settles.
-- The lock answers nothing; it is read as text only so the statement has
-- a column.
SELECT pg_advisory_xact_lock(hashtextextended('ianua.plan_counts:' || $1::uuid::text, 0))::text
    AS "held!"
