-- The latest decision a user of a tenant made about one kind of consent.
SELECT id, user_id, consent_type, granted, version, ip_address, recorded_at
FROM consent_records
WHERE tenant_id = $1 AND user_id = $2 AND consent_type = $3
ORDER BY recorded_at DESC, id DESC
LIMIT 1
