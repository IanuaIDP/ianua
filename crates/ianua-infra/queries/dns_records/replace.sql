-- Replaces every answer the zone one tenant holds for one hostname gives
-- to one name and type, and moves the zone's serial on, by a second at
-- least, when that changed what it answers. Answers whether the tenant
-- holds the zone.
WITH zone AS (
    SELECT tenant_id, hostname
    FROM dns_zones
    WHERE tenant_id = $1 AND hostname = $2
), written AS (
    INSERT INTO dns_records (tenant_id, hostname, name, kind, ttl, record_values)
    SELECT tenant_id, hostname, $3::text, $4::text, $5::integer, $6::text[]
    FROM zone
    ON CONFLICT (hostname, name, kind) DO UPDATE SET
        ttl = EXCLUDED.ttl,
        record_values = EXCLUDED.record_values
    WHERE (dns_records.ttl, dns_records.record_values)
        IS DISTINCT FROM (EXCLUDED.ttl, EXCLUDED.record_values)
    RETURNING hostname
), touched AS (
    UPDATE dns_zones
    SET changed_at = greatest(changed_at + interval '1 second', $7::timestamptz)
    WHERE tenant_id = $1 AND hostname IN (SELECT hostname FROM written)
    RETURNING hostname
)
SELECT EXISTS (SELECT 1 FROM zone) AS "held!"
