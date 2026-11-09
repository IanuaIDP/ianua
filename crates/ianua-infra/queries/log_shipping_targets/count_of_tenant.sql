-- How many places a tenant ships request records to against its plan,
-- paused ones too.
SELECT count(*) AS "count!"
FROM log_shipping_targets
WHERE tenant_id = $1
