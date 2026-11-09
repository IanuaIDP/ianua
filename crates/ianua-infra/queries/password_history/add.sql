-- Records a retired password hash of a user of a tenant at the given time,
-- or just after the latest one recorded when that is later, so each entry
-- keeps its own place in the order.
INSERT INTO password_history (tenant_id, user_id, recorded_at, password_hash)
SELECT $1, $2, GREATEST($3::timestamptz, max(recorded_at) + interval '1 microsecond'), $4::text
FROM password_history
WHERE tenant_id = $1 AND user_id = $2
