-- Takes the lease for holder $3 until $4: a new one, one this holder holds
-- already, or one that ran out before $5. Answers nothing when another
-- holder's lease still runs.
INSERT INTO platform_leases (leased, leased_id, holder, leased_until)
VALUES ($1, $2, $3, $4)
ON CONFLICT (leased, leased_id) DO UPDATE
SET holder = EXCLUDED.holder, leased_until = EXCLUDED.leased_until
WHERE platform_leases.holder = EXCLUDED.holder OR platform_leases.leased_until < $5
RETURNING leased_id
