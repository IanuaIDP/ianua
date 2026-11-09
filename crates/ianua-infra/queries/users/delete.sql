-- Removes a user of the tenant for good; what belongs to them goes with
-- them by cascade.
DELETE FROM users
WHERE tenant_id = $1 AND id = $2
