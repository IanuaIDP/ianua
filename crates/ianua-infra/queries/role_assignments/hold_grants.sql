-- Holds who holds what in one tenant (its roles given straight, its
-- groups' places and roles, its group tree) for the running transaction,
-- waiting while another transaction holds it, so a change checked against
-- what the grants would become is never raced by another such change.
-- Inside a unit of work it holds until the unit settles. The lock answers
-- nothing; it is read as text only so the statement has a column.
SELECT pg_advisory_xact_lock(hashtextextended('ianua.access_grants:' || $1::uuid::text, 0))::text
    AS "held!"
