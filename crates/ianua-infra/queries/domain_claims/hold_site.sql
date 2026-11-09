-- Holds the claims under one registrable domain for the running
-- transaction, waiting while another transaction holds them, so a check
-- of the names at, above and below one and the claim it allows are never
-- raced by a claim on a name that overlaps it. Every name that can overlap
-- another shares its registrable domain. The lock answers nothing; it is
-- read as text only so the statement has a column.
SELECT pg_advisory_xact_lock(hashtextextended('ianua.domain_claims:' || $1::text, 0))::text
    AS "held!"
