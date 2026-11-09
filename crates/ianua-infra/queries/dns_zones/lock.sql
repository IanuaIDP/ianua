-- Locks the zone one tenant holds for one hostname until the transaction
-- ends, so changes to the values of its sets run one after another.
-- Answers the hostname when the tenant holds the zone.
SELECT hostname
FROM dns_zones
WHERE tenant_id = $1 AND hostname = $2
FOR UPDATE
