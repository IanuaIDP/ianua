-- Every consent decision a user of a tenant made, of every kind, newest
-- first.
SELECT id, user_id, consent_type, granted, version, ip_address, recorded_at
FROM consent_records
WHERE tenant_id = $1 AND user_id = $2
ORDER BY recorded_at DESC, id DESC
