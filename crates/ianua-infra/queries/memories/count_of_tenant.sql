-- How many memories one tenant holds, those waiting to be deleted among
-- them.
SELECT count(*) AS "count!" FROM memories WHERE tenant_id = $1
