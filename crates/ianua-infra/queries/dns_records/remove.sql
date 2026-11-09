-- Removes every answer the zone one tenant holds for one hostname gives to
-- one name and type, and moves the zone's serial on, by a second at least,
-- when there was one.
WITH removed AS (
    DELETE FROM dns_records
    WHERE tenant_id = $1 AND hostname = $2 AND name = $3 AND kind = $4
    RETURNING hostname
)
UPDATE dns_zones
SET changed_at = greatest(changed_at + interval '1 second', $5::timestamptz)
WHERE tenant_id = $1 AND hostname IN (SELECT hostname FROM removed)
