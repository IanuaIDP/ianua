-- Holds what one organization holds against its plan itself for the
-- running transaction, waiting while another transaction holds it, so a
-- count and the creation it allows are never raced by another creation
-- counted at the same moment. Inside a unit of work it holds until the
-- unit settles. The lock answers nothing; it is read as text only so the
-- statement has a column.
SELECT pg_advisory_xact_lock(
    hashtextextended('ianua.organization_plan_counts:' || $1::uuid::text, 0))::text
    AS "held!"
