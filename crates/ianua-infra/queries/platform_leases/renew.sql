-- Extends holder $3's lease until $4. Answers nothing once another holder
-- took it over.
UPDATE platform_leases
SET leased_until = $4
WHERE leased = $1 AND leased_id = $2 AND holder = $3
RETURNING leased_id
