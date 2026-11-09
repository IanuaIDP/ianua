-- Lets go of holder $3's lease.
DELETE FROM platform_leases
WHERE leased = $1 AND leased_id = $2 AND holder = $3
